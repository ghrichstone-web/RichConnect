import os
from functools import wraps

from flask import Flask, jsonify, request, session, send_from_directory
import psycopg
from psycopg.rows import dict_row
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(os.path.dirname(BASE_DIR), "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR)
app.secret_key = os.environ["SECRET_KEY"]

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://u0_a331@localhost:5432/richconnect"
)


def get_db():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Login required"}), 401
        return fn(*args, **kwargs)

    return wrapper


@app.route("/")
def home():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/api/health")
def health():
    try:
        with get_db() as conn:
            conn.execute("SELECT 1")

        return jsonify({
            "status": "ok",
            "database": "connected"
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "database": str(e)
        }), 500


@app.post("/api/signup")
def signup():
    data = request.get_json() or {}

    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not name or not email or not password:
        return jsonify({
            "error": "Name, email and password are required"
        }), 400

    if len(password) < 6:
        return jsonify({
            "error": "Password must be at least 6 characters"
        }), 400

    password_hash = generate_password_hash(password)

    try:
        with get_db() as conn:
            user = conn.execute(
                """
                INSERT INTO users (name, email, password_hash)
                VALUES (%s, %s, %s)
                RETURNING id, name, email, bio, avatar_url, created_at
                """,
                (name, email, password_hash)
            ).fetchone()

        session["user_id"] = user["id"]

        return jsonify({
            "message": "Account created",
            "user": user
        }), 201

    except psycopg.errors.UniqueViolation:
        return jsonify({
            "error": "Email already registered"
        }), 409


@app.post("/api/login")
def login():
    data = request.get_json() or {}

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    with get_db() as conn:
        user = conn.execute(
            """
            SELECT id, name, email, password_hash, bio, avatar_url, created_at
            FROM users
            WHERE email = %s
            """,
            (email,)
        ).fetchone()

    if not user or not check_password_hash(
        user["password_hash"], password
    ):
        return jsonify({
            "error": "Invalid email or password"
        }), 401

    session["user_id"] = user["id"]

    user.pop("password_hash", None)

    return jsonify({
        "message": "Login successful",
        "user": user
    })


@app.post("/api/logout")
def logout():
    session.clear()

    return jsonify({
        "message": "Logged out"
    })


@app.get("/api/me")
@login_required
def me():
    user_id = session["user_id"]

    with get_db() as conn:
        user = conn.execute(
            """
            SELECT id, name, email, bio, avatar_url, created_at
            FROM users
            WHERE id = %s
            """,
            (user_id,)
        ).fetchone()

    if not user:
        session.clear()
        return jsonify({"error": "User not found"}), 404

    return jsonify({"user": user})


@app.get("/api/users")
@login_required
def users():
    q = request.args.get("q", "").strip()
    current_user_id = session["user_id"]

    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT
                u.id,
                u.name,
                u.email,
                u.bio,
                u.avatar_url,
                CASE
                    WHEN fr.status = 'accepted'
                        THEN 'friends'
                    WHEN fr.status = 'pending'
                         AND fr.sender_id = %s
                        THEN 'sent'
                    WHEN fr.status = 'pending'
                         AND fr.receiver_id = %s
                        THEN 'received'
                    ELSE 'none'
                END AS friend_status
            FROM users u
            LEFT JOIN friend_requests fr
              ON (
                    (fr.sender_id = %s AND fr.receiver_id = u.id)
                    OR
                    (fr.sender_id = u.id AND fr.receiver_id = %s)
                 )
            WHERE u.id <> %s
              AND (
                    %s = ''
                    OR u.name ILIKE %s
                    OR u.email ILIKE %s
                  )
            ORDER BY u.name
            LIMIT 50
            """,
            (
                current_user_id,
                current_user_id,
                current_user_id,
                current_user_id,
                current_user_id,
                q,
                f"%{q}%",
                f"%{q}%"
            )
        ).fetchall()

    return jsonify({"users": rows})


@app.get("/api/users/<int:user_id>")
def get_user(user_id):
    with get_db() as conn:
        user = conn.execute(
            """
            SELECT id, name, email, bio, avatar_url, created_at
            FROM users
            WHERE id = %s
            """,
            (user_id,)
        ).fetchone()

        if not user:
            return jsonify({"error": "User not found"}), 404

        followers = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM follows
            WHERE following_id = %s
            """,
            (user_id,)
        ).fetchone()["count"]

        following = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM follows
            WHERE follower_id = %s
            """,
            (user_id,)
        ).fetchone()["count"]

        posts_count = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM posts
            WHERE user_id = %s
            """,
            (user_id,)
        ).fetchone()["count"]

        is_following = False

        if "user_id" in session:
            is_following = conn.execute(
                """
                SELECT 1
                FROM follows
                WHERE follower_id = %s
                  AND following_id = %s
                """,
                (session["user_id"], user_id)
            ).fetchone() is not None

    return jsonify({
        "user": user,
        "followers": followers,
        "following": following,
        "posts": posts_count,
        "is_following": is_following
    })


@app.put("/api/profile")
@login_required
def update_profile():
    data = request.get_json() or {}

    name = data.get("name", "").strip()
    bio = data.get("bio", "").strip()
    avatar_url = data.get("avatar_url", "").strip()

    if not name:
        return jsonify({
            "error": "Name is required"
        }), 400

    user_id = session["user_id"]

    with get_db() as conn:
        user = conn.execute(
            """
            UPDATE users
            SET name = %s,
                bio = %s,
                avatar_url = %s
            WHERE id = %s
            RETURNING id, name, email, bio, avatar_url, created_at
            """,
            (name, bio, avatar_url, user_id)
        ).fetchone()

    return jsonify({
        "message": "Profile updated",
        "user": user
    })


@app.post("/api/follow/<int:user_id>")
@login_required
def follow(user_id):
    follower_id = session["user_id"]

    if follower_id == user_id:
        return jsonify({
            "error": "You cannot follow yourself"
        }), 400

    with get_db() as conn:
        target = conn.execute(
            "SELECT id FROM users WHERE id = %s",
            (user_id,)
        ).fetchone()

        if not target:
            return jsonify({
                "error": "User not found"
            }), 404

        conn.execute(
            """
            INSERT INTO follows (follower_id, following_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
            """,
            (follower_id, user_id)
        )

    return jsonify({
        "message": "Followed"
    })


@app.delete("/api/follow/<int:user_id>")
@login_required
def unfollow(user_id):
    follower_id = session["user_id"]

    with get_db() as conn:
        conn.execute(
            """
            DELETE FROM follows
            WHERE follower_id = %s
              AND following_id = %s
            """,
            (follower_id, user_id)
        )

    return jsonify({
        "message": "Unfollowed"
    })


@app.post("/api/friends/request/<int:user_id>")
@login_required
def send_friend_request(user_id):
    sender_id = session["user_id"]

    if sender_id == user_id:
        return jsonify({"error": "You cannot add yourself"}), 400

    with get_db() as conn:
        target = conn.execute(
            "SELECT id FROM users WHERE id = %s",
            (user_id,)
        ).fetchone()

        if not target:
            return jsonify({"error": "User not found"}), 404

        existing = conn.execute(
            """
            SELECT id, sender_id, receiver_id, status
            FROM friend_requests
            WHERE
                (sender_id = %s AND receiver_id = %s)
                OR
                (sender_id = %s AND receiver_id = %s)
            ORDER BY id DESC
            LIMIT 1
            """,
            (sender_id, user_id, user_id, sender_id)
        ).fetchone()

        if existing:
            if existing["status"] == "accepted":
                return jsonify({"error": "You are already friends"}), 400

            if (
                existing["status"] == "pending"
                and existing["receiver_id"] == sender_id
            ):
                conn.execute(
                    """
                    UPDATE friend_requests
                    SET status = 'accepted',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                    """,
                    (existing["id"],)
                )
                return jsonify({"message": "Friend request accepted"})

            if existing["status"] == "pending":
                return jsonify({"error": "Friend request already sent"}), 400

        request_row = conn.execute(
            """
            INSERT INTO friend_requests
                (sender_id, receiver_id, status)
            VALUES
                (%s, %s, 'pending')
            RETURNING id, sender_id, receiver_id, status, created_at
            """,
            (sender_id, user_id)
        ).fetchone()

    return jsonify({
        "message": "Friend request sent",
        "request": request_row
    }), 201


@app.delete("/api/friends/request/<int:user_id>")
@login_required
def cancel_friend_request(user_id):
    current_user_id = session["user_id"]

    with get_db() as conn:
        result = conn.execute(
            """
            DELETE FROM friend_requests
            WHERE sender_id = %s
              AND receiver_id = %s
              AND status = 'pending'
            RETURNING id
            """,
            (current_user_id, user_id)
        ).fetchone()

    if not result:
        return jsonify({"error": "Pending friend request not found"}), 404

    return jsonify({"message": "Friend request cancelled"})


@app.get("/api/friends/requests")
@login_required
def friend_requests():
    user_id = session["user_id"]

    with get_db() as conn:
        incoming = conn.execute(
            """
            SELECT
                fr.id,
                fr.sender_id,
                fr.receiver_id,
                fr.status,
                fr.created_at,
                u.name,
                u.email,
                u.avatar_url
            FROM friend_requests fr
            JOIN users u ON u.id = fr.sender_id
            WHERE fr.receiver_id = %s
              AND fr.status = 'pending'
            ORDER BY fr.created_at DESC
            """,
            (user_id,)
        ).fetchall()

        outgoing = conn.execute(
            """
            SELECT
                fr.id,
                fr.sender_id,
                fr.receiver_id,
                fr.status,
                fr.created_at,
                u.name,
                u.email,
                u.avatar_url
            FROM friend_requests fr
            JOIN users u ON u.id = fr.receiver_id
            WHERE fr.sender_id = %s
              AND fr.status = 'pending'
            ORDER BY fr.created_at DESC
            """,
            (user_id,)
        ).fetchall()

    return jsonify({
        "incoming": incoming,
        "outgoing": outgoing
    })


@app.post("/api/friends/requests/<int:request_id>/accept")
@login_required
def accept_friend_request(request_id):
    user_id = session["user_id"]

    with get_db() as conn:
        request_row = conn.execute(
            """
            SELECT id
            FROM friend_requests
            WHERE id = %s
              AND receiver_id = %s
              AND status = 'pending'
            """,
            (request_id, user_id)
        ).fetchone()

        if not request_row:
            return jsonify({"error": "Friend request not found"}), 404

        conn.execute(
            """
            UPDATE friend_requests
            SET status = 'accepted',
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
            """,
            (request_id,)
        )

    return jsonify({"message": "Friend request accepted"})


@app.post("/api/friends/requests/<int:request_id>/decline")
@login_required
def decline_friend_request(request_id):
    user_id = session["user_id"]

    with get_db() as conn:
        request_row = conn.execute(
            """
            SELECT id
            FROM friend_requests
            WHERE id = %s
              AND receiver_id = %s
              AND status = 'pending'
            """,
            (request_id, user_id)
        ).fetchone()

        if not request_row:
            return jsonify({"error": "Friend request not found"}), 404

        conn.execute(
            """
            UPDATE friend_requests
            SET status = 'declined',
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
            """,
            (request_id,)
        )

    return jsonify({"message": "Friend request declined"})


@app.delete("/api/friends/<int:user_id>")
@login_required
def remove_friend(user_id):
    current_user_id = session["user_id"]

    with get_db() as conn:
        deleted = conn.execute(
            """
            DELETE FROM friend_requests
            WHERE status = 'accepted'
              AND (
                    (sender_id = %s AND receiver_id = %s)
                    OR
                    (sender_id = %s AND receiver_id = %s)
              )
            RETURNING id
            """,
            (
                current_user_id,
                user_id,
                user_id,
                current_user_id
            )
        ).fetchone()

        if not deleted:
            return jsonify({"error": "You are not friends"}), 404

    return jsonify({"message": "Friend removed"})


@app.get("/api/friends")
@login_required
def get_friends():
    user_id = session["user_id"]

    with get_db() as conn:
        friends = conn.execute(
            """
            SELECT
                u.id,
                u.name,
                u.email,
                u.bio,
                u.avatar_url
            FROM friend_requests fr
            JOIN users u
              ON u.id =
                CASE
                    WHEN fr.sender_id = %s THEN fr.receiver_id
                    ELSE fr.sender_id
                END
            WHERE fr.status = 'accepted'
              AND (fr.sender_id = %s OR fr.receiver_id = %s)
            ORDER BY u.name
            """,
            (user_id, user_id, user_id)
        ).fetchall()

    return jsonify({"friends": friends})


@app.post("/api/posts")
@login_required
def create_post():
    data = request.get_json() or {}

    content = data.get("content", "").strip()

    if not content:
        return jsonify({
            "error": "Post cannot be empty"
        }), 400

    user_id = session["user_id"]

    with get_db() as conn:
        post = conn.execute(
            """
            INSERT INTO posts (user_id, content)
            VALUES (%s, %s)
            RETURNING id, user_id, content, created_at
            """,
            (user_id, content)
        ).fetchone()

    return jsonify({
        "message": "Post created",
        "post": post
    }), 201


@app.get("/api/feed")
@login_required
def feed():
    user_id = session["user_id"]

    with get_db() as conn:
        posts = conn.execute(
            """
            SELECT
                p.id,
                p.user_id,
                p.content,
                p.created_at,
                u.name,
                u.avatar_url,
                COUNT(DISTINCT l.user_id) AS likes,
                COUNT(DISTINCT c.id) AS comments,
                EXISTS (
                    SELECT 1
                    FROM likes my_like
                    WHERE my_like.post_id = p.id
                      AND my_like.user_id = %s
                ) AS liked
            FROM posts p
            JOIN users u ON u.id = p.user_id
            LEFT JOIN likes l ON l.post_id = p.id
            LEFT JOIN comments c ON c.post_id = p.id
            WHERE p.user_id = %s
               OR p.user_id IN (
                    SELECT following_id
                    FROM follows
                    WHERE follower_id = %s
               )
            GROUP BY
                p.id,
                u.name,
                u.avatar_url
            ORDER BY p.created_at DESC
            LIMIT 100
            """,
            (user_id, user_id, user_id)
        ).fetchall()

    return jsonify({
        "posts": posts
    })


@app.post("/api/posts/<int:post_id>/like")
@login_required
def like_post(post_id):
    user_id = session["user_id"]

    with get_db() as conn:
        post = conn.execute(
            "SELECT id FROM posts WHERE id = %s",
            (post_id,)
        ).fetchone()

        if not post:
            return jsonify({
                "error": "Post not found"
            }), 404

        conn.execute(
            """
            INSERT INTO likes (user_id, post_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
            """,
            (user_id, post_id)
        )

    return jsonify({
        "message": "Liked"
    })


@app.delete("/api/posts/<int:post_id>/like")
@login_required
def unlike_post(post_id):
    user_id = session["user_id"]

    with get_db() as conn:
        conn.execute(
            """
            DELETE FROM likes
            WHERE user_id = %s
              AND post_id = %s
            """,
            (user_id, post_id)
        )

    return jsonify({
        "message": "Unliked"
    })


@app.post("/api/posts/<int:post_id>/comments")
@login_required
def create_comment(post_id):
    data = request.get_json() or {}

    content = data.get("content", "").strip()

    if not content:
        return jsonify({
            "error": "Comment cannot be empty"
        }), 400

    user_id = session["user_id"]

    with get_db() as conn:
        post = conn.execute(
            "SELECT id FROM posts WHERE id = %s",
            (post_id,)
        ).fetchone()

        if not post:
            return jsonify({
                "error": "Post not found"
            }), 404

        comment = conn.execute(
            """
            INSERT INTO comments (user_id, post_id, content)
            VALUES (%s, %s, %s)
            RETURNING id, user_id, post_id, content, created_at
            """,
            (user_id, post_id, content)
        ).fetchone()

    return jsonify({
        "comment": comment
    }), 201


@app.get("/api/posts/<int:post_id>/comments")
def get_comments(post_id):
    with get_db() as conn:
        comments = conn.execute(
            """
            SELECT
                c.id,
                c.user_id,
                c.post_id,
                c.content,
                c.created_at,
                u.name,
                u.avatar_url
            FROM comments c
            JOIN users u ON u.id = c.user_id
            WHERE c.post_id = %s
            ORDER BY c.created_at ASC
            """,
            (post_id,)
        ).fetchall()

    return jsonify({
        "comments": comments
    })


@app.get("/api/messages")
@login_required
def get_conversations():
    current_user_id = session["user_id"]

    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT
                u.id AS user_id,
                u.name,
                u.avatar_url,
                m.content AS last_message,
                m.created_at AS last_message_at,
                m.sender_id AS last_sender_id
            FROM messages m
            JOIN users u
              ON u.id = CASE
                    WHEN m.sender_id = %s THEN m.receiver_id
                    ELSE m.sender_id
                 END
            WHERE m.id = (
                SELECT m2.id
                FROM messages m2
                WHERE
                    (
                        m2.sender_id = %s
                        AND m2.receiver_id = u.id
                    )
                    OR
                    (
                        m2.sender_id = u.id
                        AND m2.receiver_id = %s
                    )
                ORDER BY m2.created_at DESC, m2.id DESC
                LIMIT 1
            )
            ORDER BY m.created_at DESC, m.id DESC
            """,
            (current_user_id, current_user_id, current_user_id)
        ).fetchall()

    return jsonify({"conversations": rows})


@app.post("/api/messages")
@login_required
def send_message():
    data = request.get_json() or {}

    receiver_id = data.get("receiver_id")
    content = data.get("content", "").strip()

    if not receiver_id or not content:
        return jsonify({
            "error": "Receiver and message are required"
        }), 400

    sender_id = session["user_id"]

    with get_db() as conn:
        receiver = conn.execute(
            "SELECT id FROM users WHERE id = %s",
            (receiver_id,)
        ).fetchone()

        if not receiver:
            return jsonify({
                "error": "Receiver not found"
            }), 404

        message = conn.execute(
            """
            INSERT INTO messages
                (sender_id, receiver_id, content)
            VALUES
                (%s, %s, %s)
            RETURNING id, sender_id, receiver_id, content, created_at
            """,
            (sender_id, receiver_id, content)
        ).fetchone()

    return jsonify({
        "message": message
    }), 201


@app.get("/api/messages/<int:user_id>")
@login_required
def get_messages(user_id):
    current_user_id = session["user_id"]

    with get_db() as conn:
        messages = conn.execute(
            """
            SELECT
                id,
                sender_id,
                receiver_id,
                content,
                created_at
            FROM messages
            WHERE
                (sender_id = %s AND receiver_id = %s)
                OR
                (sender_id = %s AND receiver_id = %s)
            ORDER BY created_at ASC
            """,
            (
                current_user_id,
                user_id,
                user_id,
                current_user_id
            )
        ).fetchall()

    return jsonify({
        "messages": messages
    })


def init_db():
    schema_path = os.path.join(BASE_DIR, "schema.sql")

    with open(schema_path, "r", encoding="utf-8") as f:
        schema = f.read()

    with get_db() as conn:
        conn.execute(schema)


if __name__ == "__main__":
    init_db()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
