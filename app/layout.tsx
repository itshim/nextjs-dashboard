import '@/app/ui/global.css';
import clsx from 'clsx';
import { inter } from './ui/fonts';

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={clsx(inter.className, "antialiased")}>{children}</body>
    </html>
  );
}
