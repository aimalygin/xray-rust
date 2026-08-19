import type { Metadata } from "next";
import { headers } from "next/headers";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

async function getOrigin() {
  const headerList = await headers();
  const host = headerList.get("x-forwarded-host") ?? headerList.get("host") ?? "localhost:3000";
  const protocol = host.includes("localhost") ? "http" : "https";
  return `${protocol}://${host}`;
}

export async function generateMetadata(): Promise<Metadata> {
  const origin = await getOrigin();
  const title = "xray-rust — VLESS, REALITY, and Vision in Rust";
  const description = "An embeddable Rust client core for VLESS, REALITY, Vision, TUN, routing, and DNS, with native Apple and Android SDK packages.";

  return {
    metadataBase: new URL(origin),
    title,
    description,
    alternates: { canonical: origin },
    icons: { icon: "/favicon.svg", shortcut: "/favicon.svg" },
    openGraph: {
      type: "website",
      url: origin,
      siteName: "xray-rust",
      title,
      description,
      images: [{ url: `${origin}/og.png`, width: 1775, height: 887, alt: "xray-rust — VLESS, REALITY, Vision, Rust" }],
    },
    twitter: { card: "summary_large_image", title, description, images: [`${origin}/og.png`] },
  };
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable}`}>{children}</body>
    </html>
  );
}
