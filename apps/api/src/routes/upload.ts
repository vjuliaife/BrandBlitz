import { Router } from "express";
import { z } from "zod";
import { randomUUID } from "crypto";
import {
  PutObjectCommand,
  HeadObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { s3, BUCKETS, getPublicUrl } from "@brandblitz/storage";
import { authenticate } from "../middleware/authenticate";
import { uploadLimiter } from "../middleware/rate-limit";
import { createError } from "../middleware/error";

const router = Router();

const ALLOWED_UPLOAD_TYPES = {
  "brand-logo":    { bucket: BUCKETS.BRAND_ASSETS, prefix: "logos/",    maxMb: 2 },
  "product-image": { bucket: BUCKETS.BRAND_ASSETS, prefix: "products/", maxMb: 5 },
  "user-avatar":   { bucket: BUCKETS.BRAND_ASSETS, prefix: "avatars/",  maxMb: 1 },
} as const;

const ALLOWED_CONTENT_TYPES = [
  "image/png",
  "image/jpeg",
  "image/webp",
  "image/svg+xml",
] as const;

type AllowedMime = typeof ALLOWED_CONTENT_TYPES[number];

const PresignSchema = z.object({
  type: z.enum(["brand-logo", "product-image", "user-avatar"]),
  contentType: z.enum(["image/png", "image/jpeg", "image/webp", "image/svg+xml"]),
  contentLength: z.number().int().positive(),
});

/**
 * Detect MIME type from the first bytes of a buffer using magic numbers.
 * Returns one of the four allowed MIME strings, or null if unrecognised.
 */
function detectMime(buf: Buffer): AllowedMime | null {
  if (buf.length < 3) return null;

  // PNG: 89 50 4E 47
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) {
    return "image/png";
  }
  // JPEG: FF D8 FF
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    return "image/jpeg";
  }
  // WebP: "RIFF" at 0-3 and "WEBP" at 8-11
  if (
    buf.length >= 12 &&
    buf.toString("ascii", 0, 4) === "RIFF" &&
    buf.toString("ascii", 8, 12) === "WEBP"
  ) {
    return "image/webp";
  }
  // SVG: XML or SVG text (after optional BOM / whitespace)
  const text = buf.toString("utf8", 0, Math.min(buf.length, 128)).trimStart();
  if (text.startsWith("<svg") || text.startsWith("<?xml") || text.startsWith("<!DOCTYPE svg")) {
    return "image/svg+xml";
  }

  return null;
}

/**
 * SVG XSS patterns — any match causes the file to be rejected.
 * A single regex is not sufficient; SVGs support many execution vectors:
 *   - event handlers on any element (onload, onerror, onclick, …)
 *   - javascript: / vbscript: URIs in href/src/action/xlink:href
 *   - <foreignObject> embeds an HTML namespace (and its event model)
 *   - <use xlink:href="http://…"> pulls in external SVG fragments
 *   - data:text/html and data:text/xml URIs can carry executable HTML
 *   - <script> elements
 *
 * The full SVG content is scanned (not just the first 8 KiB) because
 * payloads can appear anywhere in the file.
 */
const SVG_DANGEROUS_PATTERNS: RegExp[] = [
  /<script/i,
  /\bon\w+\s*=/i,                         // onload=, onclick=, onerror=, …
  /javascript\s*:/i,                       // javascript: URIs
  /vbscript\s*:/i,                         // vbscript: URIs (IE legacy)
  /<foreignObject/i,                       // HTML namespace embedding
  /data\s*:\s*text\/(html|xml)/i,          // data:text/html and data:text/xml
  /<use[^>]+(?:xlink:)?href\s*=\s*["']https?:/i, // external <use> references
];

function isSvgSafe(content: string): boolean {
  return !SVG_DANGEROUS_PATTERNS.some((pattern) => pattern.test(content));
}

/**
 * POST /upload/presign
 * Generate a presigned PUT URL for direct client → storage upload.
 * Files NEVER pass through the API server — no memory pressure.
 */
router.post("/presign", authenticate, uploadLimiter, async (req, res) => {
  const { type, contentType, contentLength } = PresignSchema.parse(req.body);

  const config = ALLOWED_UPLOAD_TYPES[type];
  if (contentLength > config.maxMb * 1024 * 1024) {
    throw createError(
      `Content length exceeds maximum of ${config.maxMb}MB for ${type}`,
      400
    );
  }

  const key = `${config.prefix}${randomUUID()}`;

  const command = new PutObjectCommand({
    Bucket: config.bucket,
    Key: key,
    ContentType: contentType,
    ContentLength: contentLength,
  });

  const uploadUrl = await getSignedUrl(s3, command, { expiresIn: 60 });

  res.json({
    uploadUrl,
    key,
    publicUrl: getPublicUrl(config.bucket, key),
    expiresIn: 60,
  });
});

/**
 * POST /upload/verify
 * Verify a file was actually uploaded and its content matches the declared MIME type.
 *
 * For binary formats (PNG/JPEG/WebP): reads the first 16 bytes via a Range
 * request and validates magic bytes against the declared ContentType.
 *
 * For SVG: fetches the complete file content (bounded by the 2 MB presign limit)
 * and applies a comprehensive block-list of XSS execution vectors. A partial
 * read is not sufficient because payloads can appear anywhere in the document.
 *
 * Deletes the object and returns 400 on any validation failure.
 */
router.post("/verify", authenticate, async (req, res) => {
  const { key } = z.object({ key: z.string() }).parse(req.body);

  const bucket = key.startsWith("logos/") || key.startsWith("products/") || key.startsWith("avatars/")
    ? BUCKETS.BRAND_ASSETS
    : BUCKETS.SHARE_CARDS;

  // Step 1: confirm object exists and get its declared ContentType
  let declaredMime: string;
  try {
    const head = await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
    declaredMime = head.ContentType ?? "";
  } catch {
    throw createError("File not found in storage", 404);
  }

  // Only validate MIME for the four explicitly allowed types
  if (!(ALLOWED_CONTENT_TYPES as readonly string[]).includes(declaredMime)) {
    await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
    throw createError("Declared content type is not allowed", 400);
  }

  async function deleteAndReject(message: string): Promise<never> {
    await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
    throw createError(message, 400);
  }

  // Step 2: fetch file content for inspection
  //   - Binary formats: first 16 bytes is sufficient for magic number detection
  //   - SVG: full file required for complete XSS scanning
  const isSvg = declaredMime === "image/svg+xml";
  const rangeHeader = isSvg ? undefined : "bytes=0-15";

  let buf: Buffer;
  try {
    const obj = await s3.send(
      new GetObjectCommand({ Bucket: bucket, Key: key, Range: rangeHeader })
    );
    const bytes = await (obj.Body as { transformToByteArray(): Promise<Uint8Array> }).transformToByteArray();
    buf = Buffer.from(bytes);
  } catch {
    throw createError("Failed to read file from storage", 500);
  }

  // Step 3: validate detected MIME against declared MIME
  const detected = detectMime(buf);
  if (detected !== declaredMime) {
    return deleteAndReject("File content does not match declared content type");
  }

  // Step 4: comprehensive SVG XSS scan across the full file content
  if (isSvg && !isSvgSafe(buf.toString("utf8"))) {
    return deleteAndReject("SVG contains disallowed content");
  }

  res.json({ exists: true, publicUrl: getPublicUrl(bucket, key) });
});

export default router;
