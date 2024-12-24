const mongoose = require("mongoose");
const studentSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  username: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  mobno: {
    type: String,
    required: true,
    unique: true,
  },
  mailid: {
    type: String,
    required: true,
    unique: true,
  },
  address: {
    type: String,
    required: true,
  },
  profileimg: {
    type: String,
    required: true,
  },
});

const Register = new mongoose.model("Student", studentSchema);

module.exports = Register;
