import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { AuthProvider } from "./context/AuthContext";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "SOC Dashboard",
  description: "AI-Powered SIEM & Threat Intelligence",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body 
       className={`${geistSans.variable} ${geistMono.variable} antialiased bg-slate-900`}
       suppressHydrationWarning
      >
        {/* THIS IS THE BRAIN: Wrapping the entire app in our Auth System */}
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}