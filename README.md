# LoginVault-Secure-Access-Token-Management

Node.js Authentication API

Overview

This project is a Node.js-based server application that provides APIs for user authentication and management. It includes authentication via username/password and one-time links, along with additional features such as rate limiting, account locking, and user kickout functionality.

Features

User Authentication (Username/Password):

Supports email or phone number as a username.

Password must be at least 5 characters long.

Rate limiting implemented to prevent abuse.

Account locking after configurable failed login attempts.

User Authentication (One-Time Link):

Generates a one-time authentication link for login.

The link is valid for a configurable period.

The link can be used only once.

Get Time API:

Validates authentication token.

Responds with the server’s current time.

Returns 401 Unauthorized for invalid tokens.

Kickout API:

Admin-only API to invalidate all active tokens of a specific user.

Ensures the kicked-out user cannot access authenticated APIs.
