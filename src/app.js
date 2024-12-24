const express = require("express");
const app = express();
const path = require("path");
const hbs = require("hbs");
const crypto = require("crypto");
const port = process.env.PORT || 8000;
const cookieParser = require("cookie-parser");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const multer = require("multer");

app.use(cookieParser());
app.set("view engine", "hbs");
require("./db/conn");
app.use(express.urlencoded({ extended: false }));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

app.set("views", path.join(__dirname, "/template/views"));
const partialsPath = path.join(__dirname, "/template/partials/");
const staticPath = path.join(__dirname, "/template/");
const profileImgPath = path.join(__dirname, "uploads/profileimgs");

app.use(express.static(staticPath));
hbs.registerPartials(partialsPath);

// Temporary token store (Use a database in production)
const tokenStore = new Map();
const Register = require("./models/register");
const Complaint = require("./models/complaint");
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/profileimgs/");
  },
  filename: (req, file, cb) => {
    const uname = req.body.username;
    const ext = path.extname(file.originalname); // Get file extension (.jpg, .png)
    cb(null, `temp-${Date.now()}${path.extname(file.originalname)}`); // Temporary name
  },
});
const upload = multer({ storage: storage });

var now = new Date();
const day = now.getDate();
const month = now.getMonth() + 1; // Months are zero-based (0 = January)
const year = now.getFullYear();
const dateStr = `${day}-${month}-${year}`;
let hours = now.getHours();
let mins = now.getMinutes();
if (hours > 12) {
  hours = hours - 12;
  var a = "PM";
  if (hours < 10) {
    hours = "0" + hours;
  }
} else if (hours == 0) {
  hours = 12;
  a = "AM";
} else {
  var a = "AM";
}

if (mins < 10) {
  mins = "0" + mins;
}

//
//
//
//
//
//
//
//
//
//

app.get("/", (req, res) => {
  res.render("login");
});

app.post("/", async (req, res) => {
  try {
    const uname = req.body.username.trim().replace(/\s+/g, "");
    const pass = req.body.password;
    const resultuname = await Register.find({ username: uname });

    if (resultuname.length == 0) {
      res.render("warn", {
        desc: `NO SUCH USER HAVING USERNAME : ${uname}`,
      });
    } else {
      // Check if the password is correct by comparing hashes
      const user = resultuname[0]; // Assuming the first result is the user
      const passwordMatch = await bcrypt.compare(pass, user.password);

      if (!passwordMatch) {
        res.render("warn", {
          desc: `INVALID CREDENTIALS.`,
        });
      } else {
        // Password is valid, create a session token
        const token = crypto.randomBytes(16).toString("hex");
        tokenStore.set(token, uname);

        // Set the token in cookies for 1 hour (3600000 ms)
        res.cookie("userToken", token, { maxAge: 3600000, httpOnly: true });

        // Log the login success to a CSV file
        const date = new Date();
        const dateStr = date.toISOString().split("T")[0]; // Date in YYYY-MM-DD format
        const hours = date.getHours();
        const mins = date.getMinutes();
        const a = hours >= 12 ? "PM" : "AM";

        fs.appendFileSync(
          path.join(__dirname, "/template/stores/logs.csv"),
          `${uname},${dateStr},${"LOGIN-SUCCESS"},${hours}:${mins} ${a}\n`
        );

        // Redirect the user to their dashboard with the token
        // res.redirect(`/dashboard?user=${token}`);
        res.redirect(`/dashboard`);
      }
    }
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).render("warn", {
      desc: "Internal Server Error. Please try again later.",
    });
  }
});

//
//
//
//
//
//
//
//
//

app.get("/dashboard", async (req, res) => {
  const token = req.cookies.userToken; // Use the token from the query //CODE - TOKENCODE1

  // Check if token exists in the store
  if (tokenStore.has(token)) {
    const username = tokenStore.get(token); // Get the username from the token

    try {
      // Fetch user data using the username stored in the token
      const datas = await Register.findOne(
        { username: username },
        {
          _id: 0,
          name: 1,
          username: 1,
          mobno: 1,
          mailid: 1,
          address: 1,
          profileimg: 1,
        }
      );

      const ui = await Register.findOne({ username: username }, { _id: 1 });
      res.status(201).render("dashboard", {
        nm: datas.name,
        un: datas.username,
        mn: datas.mobno,
        mi: datas.mailid,
        ad: datas.address,
        ui: datas._id,
        pri: datas.profileimg,
      });

      // Invalidate the token after use
    } catch (err) {
      console.error("Error fetching user data:", err);
      res.status(500).render("warn", {
        desc: "Error retrieving user details. Please try again later.",
      });
    }
  } else {
    // If the token is invalid or expired, deny access
    res.status(403).render("warn", {
      desc: "Access Denied",
    });
  }
  // tokenStore.delete(token);
});

//
//
//
//
//
//
//
//
//
//

app.get("/register", (req, res) => {
  res.render("register");
});

//
//
//
//
//
//
//

app.post("/register", upload.single("profileimg"), async (req, res) => {
  try {
    const pass = req.body.password;
    const cpass = req.body.confirmpass;
    const uname = req.body.username;

    const result = await Register.find({ username: uname });

    if (pass === cpass) {
      if (result.length === 0) {
        // Hash the password before saving
        const hashedPassword = await bcrypt.hash(pass, 10); // 10 is the salt rounds
        let profileImgPath = null;

        if (req.file) {
          const tempPath = req.file.path;
          const ext = path.extname(req.file.originalname);
          const newFileName = `${uname}-profile_img${ext}`;
          const newFilePath = path.join("uploads/profileimgs/", newFileName);

          // Rename the file
          fs.renameSync(tempPath, newFilePath);
          profileImgPath = newFilePath;
        }

        const registerStudent = new Register({
          name: req.body.name.trim(),
          username: req.body.username.trim().replace(/\s+/g, ""),
          password: hashedPassword, // Store the hashed password
          mobno: req.body.mobno.trim(),
          mailid: req.body.email.trim(),
          address: req.body.address.trim(),
          profileimg: profileImgPath,
        });

        const registered = await registerStudent.save();
        fs.appendFileSync(
          path.join(__dirname, "/template/stores/registrations.csv"),
          `${uname},${pass},${req.body.mobno},${req.body.email}\n`
        );
        // Log the registration event
        const date = new Date();
        const dateStr = date.toISOString().split("T")[0]; // Date in YYYY-MM-DD format
        const hours = date.getHours();
        const mins = date.getMinutes();
        const a = hours >= 12 ? "PM" : "AM";

        fs.appendFileSync(
          path.join(__dirname, "/template/stores/logs.csv"),
          `${uname},${dateStr},${"REGISTRATION-SUCCESS"},${hours}:${mins} ${a},${
            req.body.name
          },${req.body.mobno},${req.body.email}\n`
        );

        // Responding with a successful registration message
        res.status(201).render("warn", {
          desc: "Registered Successfully",
        });
      } else {
        res.render("warn", {
          desc: "Already Data Exists with same Username.",
        });
      }
    } else {
      res.render("warn", {
        desc: "Passwords Not Matching.",
      });
    }
  } catch (err) {
    console.log(err);
    res.status(400).send(err);
  }
});

//
//
//
//
//
//
//
//
//
//
//
app.get("/update", async (req, res) => {
  const token = req.cookies.userToken;
  if (tokenStore.has(token)) {
    const username = tokenStore.get(token);
    try {
      const pw = await Register.findOne(
        { username: username },
        { _id: 0, password: 1 }
      );
      const mob = await Register.findOne(
        { username: username },
        { _id: 0, mobno: 1 }
      );
      const mail = await Register.findOne(
        { username: username },
        { _id: 0, mailid: 1 }
      );
      const add = await Register.findOne(
        { username: username },
        { _id: 0, address: 1 }
      );

      res.status(201).render("update", {
        currentPassword: pw.password,
        currentMobile: mob.mobno,
        currentEmail: mail.mailid,
        currentAddress: add.address,
      });
    } catch (err) {
      console.error("Error fetching user data:", err);
      res.status(500).render("warn", {
        desc: "Error retrieving user details. Please try again later.",
      });
    }
  } else {
    res.status(403).render("warn", {
      desc: "Access Denied",
    });
  }
});
//
//
//
//
//
//
//
//
//
//

app.post("/update", upload.single("newPic"), async (req, res) => {
  const newPass = req.body.newPassword;
  const newMob = req.body.newMobile;
  const newMail = req.body.newEmail;
  const newAdd = req.body.newAddress;

  let hashedPassword;
  if (newPass) {
    hashedPassword = await bcrypt.hash(newPass, 10);
  }

  let profileImgPath = "";

  const token = req.cookies.userToken;
  if (tokenStore.has(token)) {
    const username = tokenStore.get(token);
    try {
      // Fetch current user details from the database for comparison
      const currentUser = await Register.findOne({ username: username });

      // Build an update object dynamically
      const updateFields = {};

      // Handle file upload if present
      if (req.file) {
        const ext = path.extname(req.file.originalname);
        const datetime = Date.now(); // Get current timestamp for unique naming
        const newFileName = `${datetime}_${username}${ext}`; // New file name with timestamp
        const newFilePath = path.join("uploads/profileimgs", newFileName);

        // Step 1: Save the new file to the folder
        fs.renameSync(req.file.path, newFilePath);

        // Step 2: Delete the old file if it exists
        const oldFilePath = path.join(
          "uploads/profileimgs",
          `${username}-profile_img${ext}`
        );
        if (fs.existsSync(oldFilePath)) {
          fs.unlinkSync(oldFilePath);
        }

        // Step 3: Rename the new file to the desired filename format
        const renamedFilePath = path.join(
          "uploads/profileimgs",
          `${username}-profile_img${ext}`
        );
        fs.renameSync(newFilePath, renamedFilePath);
        profileImgPath = renamedFilePath; // Set profileImgPath to the new file path
        updateFields.profileImg = profileImgPath; // Include the profile image path for updating in the database
      }

      if (newPass) updateFields.password = hashedPassword;
      if (newMob) updateFields.mobno = newMob;
      if (newMail) updateFields.mailid = newMail;
      if (newAdd) updateFields.address = newAdd;

      // Update the document in the database
      const result = await Register.updateOne(
        { username: username }, // Filter by username
        { $set: updateFields } // Update fields
      );

      // Check if the document was updated
      if (result.modifiedCount > 0) {
        fs.appendFileSync(
          path.join(__dirname, "/template/stores/logs.csv"),
          `${username},${dateStr},${"UPDATION-SUCCESS"},${hours}:${mins} ${a}\n`
        );
        res.status(200).render("warn", {
          desc: "Details updated successfully.",
        });
        fs.appendFileSync(
          path.join(__dirname, "/template/stores/registrations.csv"),
          `${username},${newPass},${newMob},${newMail}\n`
        );
      } else {
        res.status(200).render("warn", {
          desc: "Details updated successfully.",
        });
      }
    } catch (err) {
      console.error("Error updating user details:", err);
      res.status(500).render("warn", {
        desc: "An error occurred while updating your details. Please try again later.",
      });
    }
  } else {
    res.status(403).render("warn", {
      desc: "Access Denied. Please log in again.",
    });
  }
});

//
//
//
//
//
//
//
//
//
//
app.get("/login", (req, res) => {
  res.render("login");
});

//
//
//
//
//
//
//
//
//
//
//
app.get("/delete", (req, res) => {
  res.render("delete");
});

//
//
//
//
//
//
//
//
//

app.post("/delete", async (req, res) => {
  const rpassword = req.body.password;
  const captcha = req.body.captcha;
  const token = req.cookies.userToken;

  if (tokenStore.has(token)) {
    const username = tokenStore.get(token);
    try {
      const data = await Register.findOne(
        { username: username },
        { _id: 1, password: 1 }
      );

      if (!data) {
        return res.status(404).render("404", {
          desc: "User account not found.",
        });
      }

      const curPass = data.password;
      const isMatch = await bcrypt.compare(rpassword, curPass);

      if (isMatch && (captcha === "6j4Ab" || captcha === username)) {
        const result = await Register.deleteOne({ username: username });

        if (result.deletedCount === 1) {
          const supportedExtensions = [".jpg", ".jpeg", ".png"];
          
          for (const ext of supportedExtensions) {
            const filePath = path.join(
              "./uploads/profileimgs/",
              `${username}-profile_img${ext}`
            );

            try {
              if (fs.existsSync(filePath)) {
                await fs.promises.unlink(filePath);
                break;  
              } else {
                console.log(`File not found: ${filePath}`);
              }
            } catch (unlinkErr) {
              console.error(`Error deleting ${filePath}:`, unlinkErr);
            }
          }

          return res.status(200).render("warn", {
            desc: "Deleted Successfully",
          });
        } else {
          return res.status(500).render("warn", {
            desc: "Failed To Delete",
          });
        }
      } else {
        return res.status(403).render("warn", {
          desc: "Invalid password or captcha.",
        });
      }
    } catch (err) {
      console.error(err);
      return res.status(500).render("warn", {
        desc: "An error occurred. Please try again later or raise a request in the Help section.",
      });
    }
  } else {
    return res.status(403).render("warn", {
      desc: "Access Denied. Please log in again.",
    });
  }
});


//
//
//
//
//
//
//
//
//
//
//

app.get("/complaint", (req, res) => {
  res.render("help");
  const token = req.cookies.userToken; // Use the token from the query //CODE - TOKENCODE1

  // Check if token exists in the store
  if (tokenStore.has(token)) {
    const username = tokenStore.get(token);
  }
});

//
//
//
//
//
//
//
//
//
//
//
//

app.post("/complaint", async (req, res) => {
  const token = req.cookies.userToken;

  // Check if token exists in the store
  if (tokenStore.has(token)) {
    const username = tokenStore.get(token); // Get the username associated with the token

    try {
      const complaintText = req.body.complaint; // Get the complaint text from the request body

      // Generate a unique complaint ID

      // Create a new complaint document
      const newComplaint = new Complaint({
        username: username, // Using the username from the token
        complaint: complaintText, // Complaint text from the form
      });

      // Save the complaint to the database
      const registeredComplaint = await newComplaint.save();
      const complaintId = registeredComplaint._id;
      // Render the success message
      res.status(201).render("warn", {
        desc: "Complaint Registered Successfully",
        cid: complaintId,
      });

      console.log(registeredComplaint);

      // Log the complaint registration to the log file
      fs.appendFileSync(
        path.join(__dirname, "/template/stores/logs.csv"),
        `${username},${dateStr},${"COMPLAINT-REGISTERED"},${hours}:${mins} ${a},${complaintText}\n`
      );
    } catch (err) {
      console.log(err);
      res.status(400).send(err); // Handle any errors during registration
    }
  } else {
    // If the token is invalid or expired, deny access
    res.status(403).render("warn", {
      desc: "Access Denied. Please log in again.",
    });
  }
});
//
//
//
//
//
//
//
//
//
//
//
//
//
//
app.get("/viewrequests", async (req, res) => {
  const token = req.cookies.userToken;

  if (tokenStore.has(token)) {
    const username = tokenStore.get(token);

    try {
      const complaints = await Complaint.find({ username: username });

      res.render("requests", {
        complaints: complaints,
        // You can now use this data in the 'help' view
      });
    } catch (err) {
      console.error("Error fetching complaints:", err);
      res.status(500).render("warn", {
        desc: "Error retrieving requests. Please try again later.",
      });
    }
  } else {
    res.status(403).render("warn", {
      desc: "Access Denied. Please log in again.",
    });
  }
});
//
//
//
//
//
//
//
//
//
//
app.get("/admin", async (req, res) => {
  res.render("adminverify", {
    warn: "",
  });
});
app.post("/admin", async (req, res) => {
  const username = req.body.username;
  const findUser = await Register.find({ username: username });
  const password = req.body.password;
  if (username == "admin" && password == "password") {
    const token = crypto.randomBytes(16).toString("hex");
    tokenStore.set(token, username);
    res.cookie("userToken", token, { maxAge: 3600000, httpOnly: true });
    res.redirect(`/adminpanel`);
  } else if (findUser.length > 0) {
    res.render("adminverify", {
      warn: "User is not allowed to access this route.",
    });
  } else {
    res.render("adminverify", {
      warn: "Invalid Credentials.",
    });
  }
});

app.get("/adminpanel", async (req, res) => {
  res.render("adminentry");
});

app.get("/adminviewreq", async (req, res) => {
  const token = req.cookies.userToken;

  if (tokenStore.has(token)) {
    const username = tokenStore.get(token);

    try {
      // Fetch complaints from the database (or filter by username if needed)
      const complaints = await Complaint.find();

      res.render("adminviewreq", {
        complaints: complaints,
      });
    } catch (err) {
      console.error("Error fetching complaints:", err);
      res.status(500).render("warnadmin", {
        desc: "Error retrieving complaints. Please try again later.",
      });
    }
  } else {
    res.status(403).render("warnadmin", {
      desc: "Access Denied. Please log in again.",
    });
  }
});

app.post("/adminviewreq", async (req, res) => {
  const token = req.cookies.userToken;

  if (tokenStore.has(token)) {
    const username = tokenStore.get(token);

    // Log the incoming request body to inspect the data

    // Initialize an empty object to store the cleaned-up replies
    let replies = {};

    // Loop through all keys in the req.body using Object.keys to avoid TypeError
    Object.keys(req.body).forEach((key) => {
      if (key.startsWith("reply[")) {
        // Extract the complaintId from the key (e.g., 'reply[6761ef5a3824b27c0a99784f]' => '6761ef5a3824b27c0a99784f')
        const complaintId = key.slice(6, -1); // Removing "reply[" and "]"

        // Assign the corresponding reply text to the complaint ID in the replies object
        replies[complaintId] = req.body[key];
      }
    });

    // Now replies is an object with complaintId as key and reply as value

    // Check if the replies object has valid data
    if (Object.keys(replies).length > 0) {
      try {
        // Loop through each complaintId and update the reply
        for (let complaintId in replies) {
          const reply = replies[complaintId];

          // Only update if the reply is not empty
          if (reply) {
            await Complaint.findByIdAndUpdate(complaintId, { reply: reply });
          }
        }

        // After successfully updating the replies, render success page
        res.render("warn", {
          desc: "Replies updated successfully",
        });
      } catch (err) {
        console.error("Error updating replies:", err);
        res.status(500).render("warnadmin", {
          desc: "Error updating replies. Please try again later.",
        });
      }
    } else {
      res.status(400).render("warnadmin", {
        desc: "No valid replies to update.",
      });
    }
  } else {
    res.status(403).render("warnadmin", {
      desc: "Access Denied. Please log in again.",
    });
  }
});

//
//
//
//
//
//
//
//
//
//
//
app.get("/logout", (req, res) => {
  const token = req.cookies.userToken;

  if (token) {
    tokenStore.delete(token);
    res.clearCookie("userToken", { path: "/" });
  }
  res.redirect("/login");
});
//
//
//
//
//
//
//
//
//
app.get("/logoutadmin", (req, res) => {
  const token = req.cookies.userToken;

  if (token) {
    tokenStore.delete(token);
    res.clearCookie("userToken", { path: "/" });
  }
  res.redirect("/admin");
});

//
//
//
//
//
//
//
app.get("*", (req, res) => {
  res.render("404");
});

app.listen(port);
