import NextAuth from 'next-auth';
import type { Session, User } from '@/app/lib/definitions';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import bcrypt from 'bcrypt';

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
    return user.rows[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

async function getUserByAuthenticator(authenticator: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE authenticator=${authenticator}`;
    return user.rows[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

async function getSession(token: string): Promise<Session | undefined> {
  try {
    const session = await sql<Session>`SELECT * FROM session WHERE token=${token}`;
    return session.rows[0];
  } catch(error) {
    console.error('Session does not exists:', error);
    throw new Error('Session does not exists.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      name: "credentials",
      async authorize(credentials) {
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
      },
    }),
    Credentials({
      name: "passkeys",
      async authorize(credentials, request) {
        const parsedCredentials = z
          .object({ token: z.string().uuid(), authenticator: z.string().base64() })
          .safeParse(credentials);
        if(parsedCredentials.success) {
          const {token, authenticator} = parsedCredentials.data;
          const session = await getSession(token);
          if(!session) return null;
          const authenticatedUser = await getUserByAuthenticator(authenticator);
          if(authenticatedUser) return authenticatedUser;
        }
        console.log('Invalid credentials');
        return null;
      },
    })
  ],
});
