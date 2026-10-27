// models/user.js
//cambiar type modules
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import config from '../config/config.js';
const config = configApp.get(process.env.NODE_ENV);
// desestructuracion
const { Schema, model } = mongoose;

const userSchema = new Schema({
    email: {
        type: String,
        required: true,
        trim: true,
        unique: 1
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    firstname: {
        type: String,
        maxlength: 100
    },
    lastname: {
        type: String,
        maxlength: 100
    },
    token: {
        type: String
    }
});

// Agregar async / await en las funciones 
// cambiar var por const

// Encriptar la contraseña antes de guardar el usuario
userSchema.pre('save', async function (next) {
    const user = this;
    const saltRounds = parseInt(process.env.SALT_ROUNDS, 10) || 10;

    if (user.isModified('password')) {
        //agregar try / catch
        try {
            const salt = await bcrypt.genSalt(saltRounds);
            const hash = await bcrypt.hash(user.password, salt);
            user.password = hash;
            next();
        } catch (err) {
            next(err);
        }
    } else {
        next();
    }
});

// Método para comparar contraseñas en el Login
userSchema.methods.comparePassword = async function (candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
    //eliminar if
};

// Generar Token JWT al iniciar sesión
userSchema.methods.generateToken = async function () {
    const user = this;
    const token = jwt.sign(user._id.toHexString(), config.SECRET);

    user.token = token;
    return await user.save();
    //eliminar validacion
};

// Método estático para validar un usuario mediante su Token
userSchema.statics.findByToken = async function (token) {
    const user = this;

    // usamos la decodificación directa
    const decode = jwt.verify(token, config.SECRET);
    return await user.findOne({ "_id": decode, "token": token });
};

// Eliminar token en el Logout
userSchema.methods.deleteToken = async function () {
    const user = this;
    return await user.updateOne({ $unset: { token: 1 } });
    //eliminar validacion
};

const User = model('User', userSchema);

export default User;
//exportar como default