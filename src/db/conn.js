const mongoose = require('mongoose')
mongoose.connect("mongodb://127.0.0.1:27017/Academic").then(() => {
  console.log("Database Connection Sucessfull");
}).catch((err)=>{
    console.log('No Connection')
})