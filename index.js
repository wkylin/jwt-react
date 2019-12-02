require("dotenv/config");
const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const { verify } = require("jsonwebtoken");
const { hash, compare } = require("bcryptjs");

const server = express();
server.use(cookieParser());

server.use(
    cors({
        origin: "http://localhost:3000",
        credentials: true
    })
);

server.use(express.json());
server.use(express.urlencoded({ extended: true }));

const { fakeDB } = require("./fakeDB");
const { isAuth } = require("./isAuth");

const {
    createAccessToken,
    createRefreshToken,
    sendAccessToken,
    sendRefreshToken
} = require("./tokens");

server.post("/register", async(req, res) => {
    const { email, password } = req.body;
    try {
        const user = fakeDB.find(user => user.email === email);
        if (user) throw new Error("User already exist");

        const hashedPassword = await hash(password, 10);
        fakeDB.push({
            id: fakeDB.length,
            email,
            password: hashedPassword
        });
        res.send({ message: "User Created" });
        console.log(fakeDB);
    } catch (err) {
        res.send({
            error: `${err.message}`
        });
    }
});

server.post("/login", async(req, res) => {
    const { email, password } = req.body;
    try {
        const user = fakeDB.find(user => {
            return user.email === email;
        });

        if (!user) throw new Error("User does not exist");
        const valid = await compare(password, user.password);

        if (!valid) throw new Error("Password not correct");

        const accessToken = createAccessToken(user.id);
        const refreshToken = createRefreshToken(user.id);

        // 4. Put the refreshToken in the 'database'
        user.refreshToken = refreshToken;

        console.log(fakeDB);

        // 5. Send token. RefreshToken as a cookie and ass

        sendRefreshToken(res, refreshToken);
        sendAccessToken(res, req, accessToken);
    } catch (err) {
        res.send({
            error: `${err.message}`
        });
    }
});

server.post("/logout", (req, res) => {
    res.clearCookie("refreshToken", { path: "/refresh_token" });
    return res.send({
        message: "Logged out"
    });
});

server.post("/protected", async(req, res) => {
    try {
        const userId = isAuth(req);
        if (userId !== null) {
            res.send({
                data: "This is protected data."
            });
        }
    } catch (err) {
        res.send({
            error: `${err.message}`
        });
    }
});

server.post("/refresh_token", (req, res) => {
    const token = req.cookies.refreshToken;
    if (!token) return res.send({ accessToken: "" });
    let payload = null;
    try {
        payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
    } catch (err) {
        res.send({ accessToken: "" });
    }

    const user = fakeDB.find(user => user.id === payload.userId);
    if (!user) return res.send({ accessToken: "" });
    if (user.refreshToken !== token) {
        return res.send({ accessToken: "" });
    }

    const accessToken = createAccessToken(user.id);
    const refreshToken = createRefreshToken(user.id);
    user.refreshToken = refreshToken;

    sendRefreshToken(res, refreshToken);

    return res.send({ accessToken });
});

server.listen(process.env.PORT, () => {
    console.log(`Server listening on port ${process.env.PORT}`);
});