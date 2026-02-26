# How to deploy into production with CIS compliance

## Docker configuration guide for passing in environment variables when building -arg and deploying -e

| Variable               | Environment | Deployment Method   |
| ---------------------- | ----------- | ------------------- |
| VITE_CONVEX_URL        | Client      | Docker --build-arg  |
| VITE_CONVEX_SITE_URL   | Client      | Docker --build-arg  |
| WORKOS_CLIENT_ID       | Server      | Docker -e (Runtime) |
| WORKOS_API_KEY         | Server      | Docker -e (Runtime) |
| WORKOS_COOKIE_PASSWORD | Server      | Docker -e (Runtime) |
| WORKOS_REDIRECT_URI    | Server      | Docker -e (Runtime) |
| CONVEX_DEPLOYMENT      | Server      | Docker -e (Runtime) |

## Deploy using session based environment variables

```bash
# sample docker build command WORKS!
docker build \
  --build-arg VITE_CONVEX_URL=$VITE_CONVEX_URL \
  --build-arg VITE_CONVEX_SITE_URL=$VITE_CONVEX_SITE_URL \
  -f Dockerfile.SessionEnv \
  -t odesa .
```

```bash
# without vite public variables WORKS!
docker run \
  -e WORKOS_CLIENT_ID="$WORKOS_CLIENT_ID" \
  -e WORKOS_API_KEY="$WORKOS_API_KEY" \
  -e WORKOS_COOKIE_PASSWORD="$WORKOS_COOKIE_PASSWORD" \
  -e WORKOS_REDIRECT_URI="$WORKOS_REDIRECT_URI" \
  -e CONVEX_DEPLOYMENT="$CONVEX_DEPLOYMENT" \
  -p 3000:3000 \
  -d odesa
```

## Deploy using file based env

```bash
# actual sample build WORKS AS WELL!

docker build -f Dockerfile.FileEnv -t odesa .
```

```bash
# actual docker deploy WORKS AS WELL!
docker run \
 -p 3000:3000 \
 -d -v $(pwd)/.env.local:/app/.env.local \
 odesa
```

# Welcome to your Convex + TanStack Start + WorkOS AuthKit app

This is a [Convex](https://convex.dev/) project using WorkOS AuthKit for authentication.

After the initial setup (<2 minutes) you'll have a working full-stack app using:

- Convex as your backend (database, server logic)
- [React](https://react.dev/) as your frontend (web page interactivity)
- [TanStack Start](https://tanstack.com/start) for modern full-stack React with file-based routing
- [Tailwind](https://tailwindcss.com/) for building great looking accessible UI
- [WorkOS AuthKit](https://authkit.com/) for authentication

## Get started

1. Clone this repository and install dependencies:

   ```bash
   npm install
   ```

2. Set up your environment variables:

   ```bash
   cp .env.local.example .env.local
   ```

3. Configure WorkOS AuthKit:
   - Create a [WorkOS account](https://workos.com/)
   - Get your Client ID and API Key from the WorkOS dashboard
   - In the WorkOS dashboard, add `http://localhost:3000/callback` as a redirect URI
   - Generate a secure password for cookie encryption (minimum 32 characters)
   - Update your `.env.local` file with these values

4. Configure Convex:

   ```bash
   npx convex dev
   ```

   This will:
   - Set up your Convex deployment
   - Add your Convex URL to `.env.local`
   - Open the Convex dashboard

   Then set your WorkOS Client ID in Convex:

   ```bash
   npx convex env set WORKOS_CLIENT_ID <your_client_id>
   ```

   This allows Convex to validate JWT tokens from WorkOS

5. Run the development server:

   ```bash
   npm run dev
   ```

   This starts both the Vite dev server (TanStack Start frontend) and Convex backend in parallel

6. Open [http://localhost:3000](http://localhost:3000) to see your app

## WorkOS AuthKit Setup

This app uses WorkOS AuthKit for authentication. Key features:

- **Redirect-based authentication**: Users are redirected to WorkOS for sign-in/sign-up
- **Session management**: Automatic token refresh and session handling
- **Route loader protection**: Protected routes use loaders to check authentication
- **Client and server functions**: `useAuth()` for client components, `getAuth()` for server loaders

## Learn more

To learn more about developing your project with Convex, check out:

- The [Tour of Convex](https://docs.convex.dev/get-started) for a thorough introduction to Convex principles.
- The rest of [Convex docs](https://docs.convex.dev/) to learn about all Convex features.
- [Stack](https://stack.convex.dev/) for in-depth articles on advanced topics.

## Join the community

Join thousands of developers building full-stack apps with Convex:

- Join the [Convex Discord community](https://convex.dev/community) to get help in real-time.
- Follow [Convex on GitHub](https://github.com/get-convex/), star and contribute to the open-source implementation of Convex.
