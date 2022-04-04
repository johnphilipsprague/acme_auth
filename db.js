// Contains the Sequelize data models and seeding code

const Sequelize = require("sequelize")
const { STRING } = Sequelize
const config = {
	logging: false,
}
const JWT = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const saltRounds = 10

const SECRET_KEY = process.env.JWT

if (process.env.LOGGING) {
	delete config.logging
}
const conn = new Sequelize(
	process.env.DATABASE_URL || "postgres://localhost/acme_db",
	config
)

const User = conn.define("user", {
	username: STRING,
	password: STRING,
})

User.beforeCreate(async (user) => {
	user.password = await bcrypt.hash(user.password, saltRounds)
})

User.byToken = async (token) => {
	try {
		const validToken = JWT.verify(token, SECRET_KEY)
		if (validToken) {
			const user = await User.findByPk(validToken.user)
			return user
		}

		const error = Error("bad credentials")
		error.status = 401
		throw error
	} catch (ex) {
		const error = Error("bad credentials")
		error.status = 401
		throw error
	}
}

User.authenticate = async ({ username, password }) => {
	const user = await User.findOne({
		where: {
			username,
		},
	})
	const match = await bcrypt.compare(password, user.password)

	if (match) {
		const token = JWT.sign({ userId: user.id }, SECRET_KEY)
		return token
	}
	const error = Error("bad credentials")
	error.status = 401
	throw error
}

const syncAndSeed = async () => {
	await conn.sync({ force: true })
	const credentials = [
		{ username: "lucy", password: "lucy_pw" },
		{ username: "moe", password: "moe_pw" },
		{ username: "larry", password: "larry_pw" },
	]
	const [lucy, moe, larry] = await Promise.all(
		credentials.map((credential) => User.create(credential))
	)
	return {
		users: {
			lucy,
			moe,
			larry,
		},
	}
}

module.exports = {
	syncAndSeed,
	models: {
		User,
	},
}
