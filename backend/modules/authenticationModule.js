require('dotenv').config();
const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');
const User   = require('../models/mongo/User');

const JWT_SECRET = process.env.JWT_SECRET || 'edutrack_secret_2024';

async function loginUser(username, password) {
  const user = await User.findOne({ username }).lean();
  if (!user) throw new Error('User not found');
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) throw new Error('Invalid credentials');
  const token = jwt.sign(
    { id: user._id.toString(), username: user.username, role: user.role,
      name: user.name, class: user.class, subject: user.subject,
      studentId: user.studentId },
    JWT_SECRET, { expiresIn: '8h' }
  );
  return { token, role: user.role, name: user.name,
           class: user.class, subject: user.subject,
           studentId: user.studentId };
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

async function createStudentUser({ studentId, name, className, email, password }) {
  const username = studentId.toLowerCase();
  const exists   = await User.findOne({ username });
  if (exists) return exists; // already has credentials
  const hashed = await bcrypt.hash(password || 'password', 10);
  const user = await User.create({
    username, password: hashed, role: 'student',
    name, class: className, studentId, email
  });
  return user;
}

async function deleteStudentUser(studentId) {
  await User.deleteOne({ studentId });
}

module.exports = { loginUser, verifyToken, createStudentUser, deleteStudentUser };
