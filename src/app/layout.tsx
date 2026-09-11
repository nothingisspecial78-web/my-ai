import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";

const inter = Inter({ subsets: ["latin"] });

const appUrl =
  process.env.NEXT_PUBLIC_APP_URL ||
  (process.env.VERCEL_PROJECT_PRODUCTION_URL ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}` : null) ||
  (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : null) ||
  'https://my-ai-eta-inky.vercel.app';

export const metadata: Metadata = {
  metadataBase: new URL(appUrl),
  title: "Before You Click — AI Assistant & Digital Safety",
  description: "An intelligent AI assistant that helps you think, understand, create, and stay safer before you click.",
  applicationName: "Before You Click",
  openGraph: {
    title: "Before You Click — AI Assistant & Digital Safety",
    description: "An intelligent AI assistant that helps you think, understand, create, and stay safer before you click.",
    siteName: "Before You Click",
    images: [
      {
        url: "/logo.png",
        width: 1024,
        height: 1024,
        alt: "Before You Click",
      },
    ],
    locale: "en_US",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Before You Click — AI Assistant & Digital Safety",
    description: "An intelligent AI assistant that helps you think, understand, create, and stay safer before you click.",
    images: ["/logo.png"],
  },
  icons: {
    icon: [
      { url: "/icon.png", type: "image/png" },
      { url: "/logo.png", type: "image/png" },
    ],
    apple: [
      { url: "/icon.png", type: "image/png" },
    ],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${inter.className} antialiased selection:bg-blue-100 selection:text-blue-900 dark:selection:bg-blue-900/50 dark:selection:text-blue-100`}>
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
