import type { MetadataRoute } from "next";

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    { url: "https://honeymesh.io/" },
    { url: "https://honeymesh.io/downloads" },
    { url: "https://honeymesh.io/HoneyMesh-Operator-Manual-v2.3.6-rc2.pdf" },
  ];
}
