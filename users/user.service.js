const config = require('config.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('_helpers/db');
const User = db.User;

module.exports = {
    authenticate,
    logout,
    getAll,
    getAudit,
    getById,
    create,
    update,
    delete: _delete
};

async function authenticate({ username, password }, ip) {
    const user = await User.findOne({ username });
    user.clientiplogin = ip;
    user.lastlogin = Date.now();
    await user.save();
    if (user && bcrypt.compareSync(password, user.hash)) {

        const { hash, ...userWithoutHash } = user.toObject();
        const token = jwt.sign({ sub: user.id }, config.secret);
        return {
            ...userWithoutHash,
            token
        };
    }
}


async function logout(req, ip) {

    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        jwt.verify(token, config.secret, function (err, decoded) {
            if (err) {
                return false;
            }
            req.id = decoded.sub;
        });

        const user = await User.findById(req.id).select('-hash');

        if (!user) {
            throw 'Something went wrong !';
        }
        user.clientiplogout = ip;
        user.lastlogout = Date.now();
        await user.save();
        return user;
    } else {
        return false;
    }

}

async function getAudit(req) {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        jwt.verify(token, config.secret, function (err, decoded) {
            if (err) {
                return false;
            }
            req.id = decoded.sub;
        });
        const user = await User.findById(req.id).select('-hash');
        if (user.role === "AUDITOR") {
            return await User.find().select('-hash');
        } else {
            return false;
        }
    } else {
        return false;
    }
}


async function getAll() {
    return await User.find().select('-hash');
}



async function getById(id) {
    return await User.findById(id).select('-hash');
}

async function create(userParam) {
    // validate
    if (await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    const user = new User(userParam);

    // hash password
    if (userParam.password) {
        user.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // save user
    await user.save();
}

async function update(id, userParam) {
    const user = await User.findById(id);

    // validate
    if (!user) throw 'User not found';
    if (user.username !== userParam.username && await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    // hash password if it was entered
    if (userParam.password) {
        userParam.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // copy userParam properties to user
    Object.assign(user, userParam);

    await user.save();
}

async function _delete(id) {
    await User.findByIdAndRemove(id);
}