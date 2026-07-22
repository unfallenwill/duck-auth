-- Add deletedAt to User for GDPR right-to-erasure (issue #35, Phase 4 of #30).
-- Soft delete: row stays for the retention window (30 days by default) so
-- audit logs / DSR responses can still reference the user; hard delete
-- happens via scripts/purge-deleted-users.ts after retention expires.

-- AlterTable
ALTER TABLE "User" ADD COLUMN "deletedAt" DATETIME;

-- CreateIndex
CREATE INDEX "User_deletedAt_idx" ON "User"("deletedAt");
