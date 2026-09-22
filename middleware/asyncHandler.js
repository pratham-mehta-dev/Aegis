"use strict";

// Express 4 does not catch async rejections; wrap every async route.
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

module.exports = { asyncHandler };
