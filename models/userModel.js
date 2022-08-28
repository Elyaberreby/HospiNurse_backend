const mongoose = require("mongoose");
const Joi = require("joi");
const jwt = require("jsonwebtoken");
const { config } = require("../config/secret.js")


let userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    calls: {
        type: Array,
        default: []
    },
    room: {
        type: String,
        default: "0"
    },
    role: {
        type: String,
        default: "USER"
    },
    date_created: {
        type: Date,
        default: Date.now()
    }
})


exports.UserModel = mongoose.model("users", userSchema);

exports.genToken = (_id) => {
    let token = jwt.sign({ _id }, config.tokenSecret, { expiresIn: "60mins" });
    return token;
}

exports.validateUser = (_reqBody) => {
    let joiSchema = Joi.object({
        name: Joi.string().min(2).max(100).required(),
        email: Joi.string().min(2).max(150).email().required(),
        password: Joi.string().min(3).max(100).required(),
        room: Joi.string().min(1).max(10).allow("", null)
    })
    return joiSchema.validate(_reqBody);
}


exports.validateLogin = (_reqBody) => {
    let joiSchema = Joi.object({
        email: Joi.string().min(2).max(150).email().required(),
        password: Joi.string().min(3).max(100).required()
    })
    return joiSchema.validate(_reqBody);
}

exports.validateUpdate = (_reqBody) => {
    let joiSchema = Joi.object({
        name: Joi.string().min(2).max(100).required(),
        email: Joi.string().min(2).max(150).email().required(),
        password: Joi.string().min(3).max(100).required(),
        room: Joi.string().min(1).max(10).allow("", null)
    })
    return joiSchema.validate(_reqBody);
}

exports.validateAdmin = (_reqBody) => {
    let joiSchema = Joi.object({
        name: Joi.string().min(2).max(100).required(),
        email: Joi.string().min(2).max(150).email().required(),
        password: Joi.string().min(3).max(100).required(),
        room: Joi.string().min(1).max(10).allow("", null),
        role: Joi.string().min(2).max(20).required()
    })
    return joiSchema.validate(_reqBody);
}

exports.validateCall = (_reqBody) => {
    let joiSchema = Joi.object({
        title: Joi.string().min(2).max(50).required()
    })
    return joiSchema.validate(_reqBody);
}