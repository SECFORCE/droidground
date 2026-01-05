import crypto from "crypto";

export const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

export const range = (len: number) => Array.from({ length: len }, (_x, i) => i);

export const capitalize = (s: string): string => {
  return `${s.charAt(0).toUpperCase()}${s.slice(1)}`;
};

export const randomString = (len: number): string => {
  return crypto.randomBytes(Math.ceil(len / 2)).toString("hex");
};
