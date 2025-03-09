const db = require("../models");
const config = require("../config/auth.config");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const User = db.user;
const Role = db.role;
const RefreshToken = db.refreshToken;
const Op = db.Sequelize.Op;

// Helper function to generate a unique token ID
const generateUniqueTokenId = () => {
  return require("crypto").randomBytes(10).toString("hex"); // Generates a random hex string
};

// Helper function to generate a refresh token using JWT
const generateRefreshTokenJWT = (user) => {
  return jwt.sign(
    { id: user.id, tokenId: generateUniqueTokenId() }, // Payload contains user ID and a unique token ID
    config.refreshTokenSecret,
    {
      expiresIn: config.jwtRefreshExpiration, // Refresh token expiration time
      algorithm: "HS256", // Secure signing algorithm
      allowInsecureKeySizes: true, // For development only; disable in production
    }
  );
};

/**
 * User Signup
 * - Creates a new user with hashed password
 * - Assigns roles (if provided)
 */
exports.signup = async (req, res) => {
  try {
    console.log("req.body", req.body);

    // Create a new user with hashed password
    const user = await User.create({
      username: req.body.email,
      email: req.body.email,
      password: bcrypt.hashSync(req.body.password, 8),
    });

    // Assign roles if provided, otherwise assign default role
    if (req.body.roles) {
      const roles = await Role.findAll({
        where: { name: { [Op.or]: req.body.roles } },
      });
      await user.setRoles(roles);
    } else {
      await user.setRoles([1]); // Default role ID (assuming 1 is the default)
    }

    res.status(201).send({ message: "User was registered successfully!" });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};

/**
 * User Signin
 * - Authenticates user credentials
 * - Generates JWT access and refresh tokens
 */
exports.signin = async (req, res) => {
  try {
    // Find user by email
    const user = await User.findOne({ where: { username: req.body.email } });

    if (!user) {
      return res.status(404).send({ message: "User Not Found." });
    }

    // Validate password
    const passwordIsValid = bcrypt.compareSync(
      req.body.password,
      user.password
    );
    if (!passwordIsValid) {
      return res
        .status(401)
        .send({ accessToken: null, message: "Invalid Password!" });
    }

    // Generate Access Token
    const accessToken = jwt.sign({ id: user.id }, config.secret, {
      expiresIn: config.jwtAccessExpiration, // Access token expiration
      algorithm: "HS256",
      allowInsecureKeySizes: true, // For development only
    });

    // Generate and store Refresh Token
    const refreshToken = await RefreshToken.create({
      token: generateRefreshTokenJWT(user),
      userId: user.id,
      expiryDate: new Date(Date.now() + config.jwtRefreshExpiration * 1000),
    });

    // Get user roles
    const roles = await user.getRoles();
    const authorities = roles.map((role) => `ROLE_${role.name.toUpperCase()}`);

    // Send response with tokens
    res.status(200).send({
      id: user.id,
      username: user.email,
      email: user.email,
      roles: authorities,
      accessToken: accessToken,
      refreshToken: refreshToken.token,
    });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};

/**
 * Refresh Access Token
 * - Validates refresh token
 * - Generates a new access token
 * - Issues a new refresh token to prevent token reuse attacks
 */
exports.refreshAccessToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(403).json({ message: "Refresh token is required!" });
    }

    // Retrieve refresh token from database
    const storedToken = await RefreshToken.findOne({
      where: { token: refreshToken },
    });

    if (!storedToken) {
      return res.status(403).json({ message: "Invalid refresh token!" });
    }

    // Check if the refresh token has expired
    if (storedToken.expiryDate.getTime() < Date.now()) {
      await storedToken.destroy(); // Remove expired token
      return res
        .status(403)
        .json({ message: "Refresh token expired. Please sign in again." });
    }

    // Verify JWT integrity
    const decoded = jwt.verify(refreshToken, config.refreshTokenSecret);

    // Generate a new access token
    const newAccessToken = jwt.sign({ id: decoded.id }, config.secret, {
      expiresIn: config.jwtAccessExpiration, // New access token expiration
      algorithm: "HS256",
      allowInsecureKeySizes: true, // Only for development
    });

    // Optional: Generate a new refresh token to prevent token reuse attacks
    const newRefreshToken = await RefreshToken.create({
      token: generateRefreshTokenJWT({ id: decoded.id }),
      userId: decoded.id,
      expiryDate: new Date(Date.now() + config.jwtRefreshExpiration * 1000),
    });

    // Remove old refresh token to enhance security
    await storedToken.destroy();

    // Send response with new tokens
    return res.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken.token,
    });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Could not refresh token", error: err.message });
  }
};
