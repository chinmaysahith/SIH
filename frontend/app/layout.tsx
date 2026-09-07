import type { Metadata } from "next";
import React from "react";

export const metadata: Metadata = {
  title: "Email Fraud Forensic Analysis Platform",
  description: "Stage 0 Project Setup Skeleton",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          padding: 0,
          fontFamily:
            "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
          backgroundColor: "#0d1117",
          color: "#c9d1d9",
        }}
      >
        {children}
      </body>
    </html>
  );
}
