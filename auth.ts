import NextAuth from 'next-auth';
import type { Passkey, Session, User } from '@/app/lib/definitions';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import Passkeys from 'next-auth/providers/passkey';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import bcrypt from 'bcrypt';
import { VerifiedAuthenticationResponse, VerifyAuthenticationResponseOpts, generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';
import { AuthenticationResponseJSON } from '@simplewebauthn/types';
import { rpID, rpName, origin } from './app/lib/constants';
import adapter from './auth.adapter';
import base64url from 'base64url';

export async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
    return user.rows[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export async function getUserByAuthenticator(publicKey: string): Promise<string | undefined> {
  try {
    const user = await sql<Passkey>`SELECT * FROM passkeys WHERE publicKey=${publicKey}`;
    return user.rows[0].userId;
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export async function getSession(challenge: string): Promise<Session | undefined> {
  try {
    const session = await sql<Session>`SELECT * FROM session WHERE challenge=${challenge}`;
    return session.rows[0];
  } catch(error) {
    console.error('Session does not exists:', error);
    throw new Error('Session does not exists.');
  }
}

export async function getUserPasskey(user: User) {
  try {
    console.log(user, "user");
    const passkey = await sql`SELECT * FROM passkeys WHERE user_id=${user.email}`;
    return passkey.rows as Passkey[];
  } catch (error) {
    console.error('Failed to fetch passkey:', error);
    throw new Error('Failed to fetch passkey.');
  }
}



export async function getAuthenticationWithPasskeys(options: VerifyAuthenticationResponseOpts): Promise<VerifiedAuthenticationResponse> {
    console.log("passkeysss", options);
    const challenge= options.expectedChallenge as string;
    const cred = options.response as AuthenticationResponseJSON;
    const user = await getUserByAuthenticator(cred.rawId);
    const currentSessionId = (await getSession(challenge))?.session_token;
    if (!user) return {
      verified: false,
      authenticationInfo: {
        credentialID: new Uint8Array(Buffer.from(options.response.id)),
        newCounter: 0,
        userVerified: false,
        credentialBackedUp: false,
        credentialDeviceType: "singleDevice",
        origin,
        rpID: rpID as string
      }
    };
    const verification = await verifyAuthenticationResponse({
      response: cred,
      expectedChallenge: currentSessionId || "",
      expectedOrigin: origin,
      expectedRPID: rpID as string,
      authenticator: options.authenticator
    });
    const userInfo = await getUser(user);
    if(!userInfo) return {
      verified: false,
      authenticationInfo: {
        credentialID: new Uint8Array(Buffer.from(options.response.id)),
        newCounter: 0,
        userVerified: false,
        credentialBackedUp: false,
        credentialDeviceType: "singleDevice",
        origin,
        rpID: rpID as string
      }
    };
    return verification;
}

export const { auth, handlers, signIn, signOut } = NextAuth({
  ...authConfig,
  adapter: adapter(),
  debug: true,
  experimental: {
    enableWebAuthn: true
  },
  providers: [
    Credentials({
      async authorize(credentials) {
        console.log("cred");
        if(credentials.authType === "passkeys") {
          const parsedCredentials = JSON.parse(credentials?.credentials as string);
          console.log("cred", parsedCredentials);
          const userHandle = base64url.decode(parsedCredentials.response.userHandle);
          const authenticatorData = base64url.decode(parsedCredentials.response.authenticatorData);
          const clientDataJSON = base64url.decode(parsedCredentials.response.clientDataJSON);
          const signature = base64url.decode(parsedCredentials.response.signature);
          const rawId = base64url.decode(parsedCredentials.response.rawId);
          const id = base64url.decode(parsedCredentials.response.id);
          const user = await getUserByAuthenticator(rawId);
          const verification = await verifyRegistrationResponse({
            response: parsedCredentials.response,
            expectedChallenge: JSON.parse(clientDataJSON).challenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
          }).catch(e => console.log(e));
          console.log("cred", userHandle, authenticatorData, clientDataJSON, signature, verification);
          return null;
        }
        else {
          const parsedCredentials = z
            .object({ email: z.string().email(), password: z.string().min(6) })
            .safeParse(credentials);
          if (parsedCredentials.success) {
            const { email, password } = parsedCredentials.data;
            const user = await getUser(email);
            if (!user) return null;
            const passwordsMatch = await bcrypt.compare(password, user.password);
            if (passwordsMatch) return user;
          }
          console.log('Invalid credentials');
          return null;
        }
      },
    }),
    // Passkeys
    // Passkeys({
    //   name: "passkeys",
    //   relayingParty: {
    //     id: rpID,
    //     name: rpName,
    //     origin
    //   },
    //   simpleWebAuthn: {
    //     verifyAuthenticationResponse: getAuthenticationWithPasskeys,
    //     verifyRegistrationResponse: verifyRegistrationResponse,
    //     generateAuthenticationOptions: generateAuthenticationOptions,
    //     generateRegistrationOptions: generateRegistrationOptions
    //   },
    //   enableConditionalUI: true,
      // async authorize(credentials) {
      //   console.log("passkeysss", credentials);
      //   const parsedCredentials = z
      //     .object({ credentials: z.string(), challenge: z.string() })
      //     .safeParse(credentials);
      //   if (parsedCredentials.success) {
      //     const { credentials, challenge } = parsedCredentials.data;
      //     const cred = JSON.parse(credentials) as RegistrationResponseJSON;
      //     const user = await getUserByAuthenticator(cred.rawId);
      //     const currentSessionId = (await getSession(challenge))?.challenge;
      //     if (!user) return null;
      //     const verification = await verifyRegistrationResponse({
      //       response: cred,
      //       expectedChallenge: currentSessionId || "",
      //       expectedOrigin: origin,
      //       expectedRPID: rpID,
      //     });
      //     const userInfo = await getUser(user);
      //     if(!userInfo) return null;
      //     return userInfo;
      //   }
      //   console.log('Invalid credentials');
      //   return null;
      // },
    // })
  ],
});
