const { verify } = require("jsonwebtoken");

const isAuth = req => {
    // console.log("req.header", req.headers);
    const authorization = req.headers["authorization"];

    if (!authorization) throw new Error("You need to login");

    // 'Bearer xxx'
    const token = authorization.split(" ")[1];

    const { userId } = verify(token, process.env.ACCESS_TOKEN_SECRET);

    return userId;
};

module.exports = {
    isAuth
};