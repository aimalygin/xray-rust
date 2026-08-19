import type { MetadataRoute } from "next";
import { headers } from "next/headers";

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const headerList = await headers();
  const host = headerList.get("x-forwarded-host") ?? headerList.get("host") ?? "localhost:3000";
  const protocol = host.includes("localhost") ? "http" : "https";

  return [{ url: `${protocol}://${host}`, changeFrequency: "weekly", priority: 1 }];
}
