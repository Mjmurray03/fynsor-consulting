#!/bin/bash
# Fynsor Autonomous Website Builder

echo '[FYNSOR BUILD] Starting autonomous website generation...'

# Step 1: Initialize project
echo '[1/6] Initializing Next.js project with security-first configuration...'
npx create-next-app@latest fynsor-consulting \
  --typescript \
  --tailwind \
  --app \
  --import-alias '@/*'

cd fynsor-consulting

# Step 2: Install security dependencies
echo '[2/6] Installing security and infrastructure packages...'
npm install \
  @supabase/supabase-js \
  @supabase/auth-helpers-nextjs \
  bcryptjs \
  jsonwebtoken \
  helmet \
  express-rate-limit \
  zod \
  @sentry/nextjs \
  winston \
  crypto-js

# Step 3: Execute security setup
echo '[3/6] Implementing security infrastructure...'
claude-swarm execute security-setup.yaml

# Step 4: Build all components in parallel
echo '[4/6] Building website components (parallel execution)...'
claude-swarm execute --parallel component-build.yaml

# Step 5: Run security audit
echo '[5/6] Running comprehensive security audit...'
npm audit
npm run security:scan
npm run test:security

# Step 6: Deploy
echo '[6/6] Deploying to production...'
vercel --prod --yes

echo '[FYNSOR BUILD] ✅ Website successfully built and deployed!'
echo 'Access at: https://fynsor.com'