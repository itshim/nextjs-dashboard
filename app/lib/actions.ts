'use server';
import { sql } from '@vercel/postgres';
import { AuthError } from 'next-auth';
import { signIn } from '@/auth';
import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { z } from 'zod';
import { BuiltInProviderType } from 'next-auth/providers';
import { v4 } from "uuid";
import { getUser, getUserPasskey } from './data';
import { generateRegistrationOptions } from '@simplewebauthn/server';
import { rpID, rpName } from './constants';
import {AuthenticatorTransportFuture, PublicKeyCredentialCreationOptionsJSON} from "@simplewebauthn/types"
import { cookies } from 'next/headers';

const FormSchema = z.object({
  id: z.string(),
  customerId: z.string({
    invalid_type_error: 'Please select a customer.',
  }),
  amount: z.coerce
    .number()
    .gt(0, { message: 'Please enter an amount greater than $0.' }),
  status: z.enum(['pending', 'paid'], {
    invalid_type_error: 'Please select an invoice status.',
  }),
  date: z.string(),
});

const CreateInvoice = FormSchema.omit({ id: true, date: true });

export type State = {
  errors?: {
    customerId?: string[];
    amount?: string[];
    status?: string[];
  };
  message?: string | null;
};

export async function createInvoice(prevState: State, formData: FormData) {
  try {
    const validatedFields = CreateInvoice.safeParse({
      customerId: formData.get('customerId'),
      amount: formData.get('amount'),
      status: formData.get('status'),
    });
    if (!validatedFields.success) {
      return {
        errors: validatedFields.error.flatten().fieldErrors,
        message: 'Missing Fields. Failed to Create Invoice.',
      };
    }
    const { customerId, amount, status } = validatedFields.data;
    const amountInCents = amount * 100;
    const date = new Date().toISOString().split('T')[0];
    await sql`
    INSERT INTO invoices (customer_id, amount, status, date)
    VALUES (${customerId}, ${amountInCents}, ${status}, ${date})
  `;
  } catch (e) {
    return {
      message: 'Database Error: Failed to Create Invoice.',
    };
  }
  revalidatePath('/dashboard/invoices');
  redirect('/dashboard/invoices');
}

const UpdateInvoice = FormSchema.omit({ id: true, date: true });

export async function updateInvoice(id: string, formData: FormData) {
  try {
    const { customerId, amount, status } = UpdateInvoice.parse({
      customerId: formData.get('customerId'),
      amount: formData.get('amount'),
      status: formData.get('status'),
    });

    const amountInCents = amount * 100;

    await sql`
      UPDATE invoices
      SET customer_id = ${customerId}, amount = ${amountInCents}, status = ${status}
      WHERE id = ${id}
    `;
  } catch (e) {
    return {
      message: 'Database Error: Failed to Edit Invoice.',
    };
  }
  revalidatePath('/dashboard/invoices');
  redirect('/dashboard/invoices');
}

export async function deleteInvoice(id: string) {
  try {
    await sql`DELETE FROM invoices WHERE id = ${id}`;
    revalidatePath('/dashboard/invoices');
  } catch (e) {
    return {
      message: 'Database Error: Failed to Delete Invoice.',
    };
  }
}

export async function authenticate(
  prevState: string | undefined,
  formData: FormData,
) {
  try {
    await signIn(formData.get("type") as BuiltInProviderType || "credentials", formData);
    const email = formData.get("email");
    email && cookies().set('username', email as string)
  } catch (error) {
    if (error instanceof AuthError) {
      switch (error.type) {
        case 'CredentialsSignin':
          return 'Invalid credentials.';
        default:
          return 'Something went wrong.';
      }
    }
    throw error;
  }
}

export async function createSession(): Promise<BufferSource> {
  try {
    const challenge = v4();
    await sql`
    INSERT INTO sessions (challenge)
    VALUES (${challenge})
  `;
  return Buffer.from(challenge);
  } catch(error) {
    throw error;
  }
}

export async function generateCredentialOptions(userName: string): Promise<PublicKeyCredentialCreationOptionsJSON>  {
  const user = await getUser(userName);
  if(!user) throw new Error("User not found")
  const userPasskey = await getUserPasskey(user);
  const credentialOptions = await generateRegistrationOptions({
    rpID,
    rpName,
    userName,
    userID: userName,
    attestationType: "none",
    excludeCredentials: userPasskey.map(u => ({
      id: u.publicKey,
      type: "public-key",
      transports: (u.transports?.split(",") || []) as AuthenticatorTransportFuture[]
    })),
    authenticatorSelection: {
      // Defaults
      residentKey: 'preferred',
      userVerification: 'preferred',
      // Optional
      authenticatorAttachment: 'platform',
    },
  });
  console.log(credentialOptions, "credentialOption")
  return credentialOptions;
}

export async function registerPasskeys(userName: string, publicKey: string, transports: AuthenticatorTransportFuture): Promise<PublicKeyCredentialCreationOptionsJSON> {
  try {
    const credentialOptions = await generateCredentialOptions(userName);
    await sql`
    INSERT INTO passkeys (id, publicKey, user, transports)
    VALUES (${Buffer.from(publicKey).toString('base64')}, ${publicKey}, ${userName}, ${transports})
  `;
    return credentialOptions;
  } catch(err) {
    throw err;
  }
}
