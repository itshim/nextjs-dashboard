"use client";

import { lusitana } from '@/app/ui/fonts';
import {
  AtSymbolIcon,
  KeyIcon,
  ExclamationCircleIcon,
} from '@heroicons/react/24/outline';
import { ArrowRightIcon } from '@heroicons/react/20/solid';
import { Button } from './button';
import { useFormState, useFormStatus } from 'react-dom';
import { authenticate, createSession } from '../lib/actions';
import { useEffect, useRef } from 'react';

function _arrayBufferToBase64( buffer: ArrayBuffer ) {
  var binary = '';
  var bytes = new Uint8Array( buffer );
  var len = bytes.byteLength;
  for (var i = 0; i < len; i++) {
      binary += String.fromCharCode( bytes[ i ] );
  }
  return window.btoa( binary );
}

export default function LoginForm() {
  const [errorMessage, dispatch] = useFormState(authenticate, undefined);
  const isPending = useRef<boolean>(false);
  useEffect(() => {
    async function getPasskey() {
      if(isPending.current) return;
      isPending.current = true;
      const challengeBuffer = await createSession();
      const challenge = new Int32Array(challengeBuffer as ArrayBufferLike);
      const options: PublicKeyCredentialRequestOptions  = {
        challenge,
        rpId: process.env.NEXT_DOMAIN,
        allowCredentials: [],
        timeout: 1000,
        userVerification: "preferred"
      }
     const credentials = await navigator.credentials.get({
      publicKey: options, 
      mediation: "conditional", 
      password: true
    }) as PublicKeyCredential; 
     const userHandleBuffer = (credentials.response as AuthenticatorAssertionResponse).userHandle;
     console.log(credentials);
     const clientDataJSON = _arrayBufferToBase64(credentials.response.clientDataJSON);
     const authenticatorData = _arrayBufferToBase64((credentials.response as AuthenticatorAssertionResponse).authenticatorData);
     const signature = _arrayBufferToBase64((credentials.response as AuthenticatorAssertionResponse).signature);
     const rawId = _arrayBufferToBase64(credentials.rawId);
     const id = credentials.id;
     const userHandle = userHandleBuffer ? _arrayBufferToBase64(userHandleBuffer) : null;
     const response = {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle,
      rawId,
      id
     };
     const cred = {
      ...credentials,
      response
     }
     const data = new FormData();
     data.append("authType", "passkeys");
     data.append("credentials", JSON.stringify(cred));
    //  data.append("challenge", challengeBuffer.toString());
     isPending.current = false;
     dispatch(data);
    //  data.append("email", credentials.response.clientDataJSON);
    }
    getPasskey();
  }, []);

  return (
    <form className="space-y-3" action={dispatch}>
      <div className="flex-1 rounded-lg bg-gray-50 px-6 pb-4 pt-8">
        <h1 className={`${lusitana.className} mb-3 text-2xl`}>
          Please log in to continue.
        </h1>
        <div className="w-full">
          <div>
            <label
              className="mb-3 mt-5 block text-xs font-medium text-gray-900"
              htmlFor="email"
            >
              Email
            </label>
            <div className="relative">
              <input
                className="peer block w-full rounded-md border border-gray-200 py-[9px] pl-10 text-sm outline-2 placeholder:text-gray-500"
                id="email"
                type="email"
                name="email"
                placeholder="Enter your email address"
                autoComplete="username webauthn"
                required
              />
              <AtSymbolIcon className="pointer-events-none absolute left-3 top-1/2 h-[18px] w-[18px] -translate-y-1/2 text-gray-500 peer-focus:text-gray-900" />
            </div>
          </div>
          <div className="mt-4">
            <label
              className="mb-3 mt-5 block text-xs font-medium text-gray-900"
              htmlFor="password"
            >
              Password
            </label>
            <div className="relative">
              <input
                className="peer block w-full rounded-md border border-gray-200 py-[9px] pl-10 text-sm outline-2 placeholder:text-gray-500"
                id="password"
                type="password"
                name="password"
                placeholder="Enter password"
                autoComplete="current-password webauthn"
                required
                minLength={6}
              />
              <KeyIcon className="pointer-events-none absolute left-3 top-1/2 h-[18px] w-[18px] -translate-y-1/2 text-gray-500 peer-focus:text-gray-900" />
            </div>
          </div>
        </div>
        <LoginButton />
        <div
          className="flex h-8 items-end space-x-1"
          aria-live="polite"
          aria-atomic="true"
        >
          {errorMessage && (
            <>
              <ExclamationCircleIcon className="h-5 w-5 text-red-500" />
              <p className="text-sm text-red-500">{errorMessage}</p>
            </>
          )}
        </div>
      </div>
    </form>
  );
}

function LoginButton() {
  const { pending } = useFormStatus();
  return (<>
    <Button className="mt-4 w-full" aria-disabled={pending}>
      Log in <ArrowRightIcon className="ml-auto h-5 w-5 text-gray-50" />
    </Button>
    </>
  );
}
