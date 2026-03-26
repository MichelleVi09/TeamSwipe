# TeamSwipe

TeamSwipe is a Flask web application built to help players find teammates for multiplayer games. Users can create squad posts, browse other players' posts, filter by game or tags, and use a swipe-style invite flow to connect with others.

## Features

- User registration and login
- Secure password hashing with `bcrypt`
- Create and delete squad posts
- Browse active posts in a grid layout
- Filter posts by game and tags
- Swipe mode for filtered posts
- Invite request workflow
- Notifications for incoming and sent requests
- Discord username sharing after invite approval
- Dynamic game cover lookup using Twitch/IGDB
- MongoDB storage for users, posts, cached game covers, and invite activity
- Contact form powered by FormSubmit

## Tech Stack

- Python
- Flask
- MongoDB
- PyMongo
- Jinja2
- HTML / CSS / JavaScript
- Twitch API / IGDB API
- FormSubmit
