-- Failure observations remain in the failures table for threshold detection.
-- The aggregate failure count is not part of a desired ban decision.
ALTER TABLE decisions DROP COLUMN failures;
