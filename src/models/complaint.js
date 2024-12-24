const mongoose= require('mongoose')
const complaintSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    complaint: {
        type: String,
        required: true,
    },
    reply: {
        type: String,
        sparse: true 
    }
})


const Complaint = new mongoose.model('complaint',complaintSchema)

module.exports = Complaint