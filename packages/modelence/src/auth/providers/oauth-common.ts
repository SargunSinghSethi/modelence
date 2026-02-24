import { type Request, type Response } from 'express';
import { ObjectId } from 'mongodb';
import { usersCollection } from '@/auth/db';
import { createSession } from '@/auth/session';
import { getAuthConfig } from '@/app/authConfig';
import { getCallContext } from '@/app/server';
import { getConfig } from '@/config/server';

export interface OAuthUserData {
  id: string;
  email: string;
  emailVerified: boolean;
  providerName: 'google' | 'github';
}

export async function authenticateUser(res: Response, userId: ObjectId) {
  const { authToken } = await createSession(userId);

  res.cookie('authToken', authToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  });
  res.status(301);
  res.redirect('/');
}

export function getRedirectUri(provider: string): string {
  return `${getConfig('_system.site.url')}/api/_internal/auth/${provider}/callback`;
}

export async function handleOAuthUserAuthentication(
  req: Request,
  res: Response,
  userData: OAuthUserData
): Promise<void> {
  const existingUser = await usersCollection.findOne({
    [`authMethods.${userData.providerName}.id`]: userData.id,
  });

  const { session, connectionInfo } = await getCallContext(req);

  try {
    if (existingUser) {
      if (existingUser.status === 'disabled' || existingUser.status === 'deleted') {
        res.status(400).json({
          error: 'User account is not active.',
        });
        return;
      }

      await authenticateUser(res, existingUser._id);

      getAuthConfig().onAfterLogin?.({
        provider: userData.providerName,
        user: existingUser,
        session,
        connectionInfo,
      });
      getAuthConfig().login?.onSuccess?.(existingUser);

      return;
    }
  } catch (error) {
    if (error instanceof Error) {
      getAuthConfig().login?.onError?.(error);

      getAuthConfig().onLoginError?.({
        provider: userData.providerName,
        error,
        session,
        connectionInfo,
      });
    }
    throw error;
  }

  if (!userData.email) {
    res.status(400).json({
      error: `Email address is required for ${userData.providerName} authentication.`,
    });
    return;
  }

  let existingUserByEmail;

  try {
    existingUserByEmail = await usersCollection.findOne(
      { 'emails.address': userData.email, status: { $ne: 'deleted' } },
      { collation: { locale: 'en', strength: 2 } }
    );
  } catch (error) {
    if (error instanceof Error) {
      getAuthConfig().onSignupError?.({
        provider: userData.providerName,
        error,
        session,
        connectionInfo,
      });

      getAuthConfig().signup?.onError?.(error);
    }
    throw error;
  }

  if (existingUserByEmail) {
    if (existingUserByEmail.status === 'disabled') {
      res.status(400).json({
        error: 'User account is not active.',
      });
      return;
    }

    const linkingMode = getAuthConfig().oauthAccountLinking ?? 'manual';
    const matchedEmail = existingUserByEmail.emails?.find(
      (emailDoc) => emailDoc.address.toLowerCase() === userData.email.toLowerCase()
    );

    if (linkingMode === 'auto' && userData.emailVerified) {
      // Prevent pre-registration takeover by requiring local ownership verification too.
      if (!matchedEmail?.verified) {
        res.status(400).json({
          error: 'User with this email already exists. Please log in instead.',
        });
        return;
      }

      try {
        const updateResult = await usersCollection.updateOne(
          {
            _id: existingUserByEmail._id,
            status: { $nin: ['deleted', 'disabled'] },
            [`authMethods.${userData.providerName}.id`]: { $exists: false },
          },
          { $set: { [`authMethods.${userData.providerName}.id`]: userData.id } }
        );

        let autoLinkSuccessful = updateResult.matchedCount > 0;

        if (!autoLinkSuccessful) {
          // Check if provider is already linked now (race case)
          const providerLinkedUser = await usersCollection.findOne({
            [`authMethods.${userData.providerName}.id`]: userData.id,
          });

          if (
            providerLinkedUser &&
            providerLinkedUser._id.equals(existingUserByEmail._id) &&
            providerLinkedUser.status !== 'disabled' &&
            providerLinkedUser.status !== 'deleted'
          ) {
            autoLinkSuccessful = true;
          }
        }

        if (!autoLinkSuccessful) {
          // User was deleted/disabled between findOne and updateOne, or linked to a *different* ID
          res.status(400).json({
            error: 'User with this email already exists. Please log in instead.',
          });
          return;
        }

        await authenticateUser(res, existingUserByEmail._id);

        // Re-fetch user to provide fresh data (including newly linked authMethods) to callbacks
        const updatedUser =
          (await usersCollection.findOne(
            { _id: existingUserByEmail._id },
            { readPreference: 'primary' }
          )) ?? existingUserByEmail;

        getAuthConfig().onAfterLogin?.({
          provider: userData.providerName,
          user: updatedUser,
          session,
          connectionInfo,
        });
        getAuthConfig().login?.onSuccess?.(updatedUser);

        return;
      } catch (error) {
        if (error instanceof Error) {
          getAuthConfig().login?.onError?.(error);

          getAuthConfig().onLoginError?.({
            provider: userData.providerName,
            error,
            session,
            connectionInfo,
          });
        }
        throw error;
      }
    }

    // Manual mode (default) or unverified email — reject
    // TODO: handle case with an HTML page
    res.status(400).json({
      error: 'User with this email already exists. Please log in instead.',
    });
    return;
  }

  // If the user does not exist, create a new user
  try {
    const newUser = await usersCollection.insertOne({
      handle: userData.email,
      status: 'active',
      emails: [
        {
          address: userData.email,
          verified: userData.emailVerified,
        },
      ],
      createdAt: new Date(),
      authMethods: {
        [userData.providerName]: {
          id: userData.id,
        },
      },
    });

    await authenticateUser(res, newUser.insertedId);

    const userDocument = await usersCollection.findOne(
      { _id: newUser.insertedId },
      { readPreference: 'primary' }
    );

    if (userDocument) {
      getAuthConfig().onAfterSignup?.({
        provider: userData.providerName,
        user: userDocument,
        session,
        connectionInfo,
      });

      getAuthConfig().signup?.onSuccess?.(userDocument);
    }
  } catch (error) {
    if (error instanceof Error) {
      getAuthConfig().onSignupError?.({
        provider: userData.providerName,
        error,
        session,
        connectionInfo,
      });

      getAuthConfig().signup?.onError?.(error);
    }
    throw error;
  }
}

export function validateOAuthCode(code: unknown): string | null {
  if (!code || typeof code !== 'string') {
    return null;
  }
  return code;
}
