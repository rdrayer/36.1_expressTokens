/** User class for message.ly */

const db = require("../db");
const ExpressError = require("../expressError");
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require('../config');

/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) {
    try {
      const { username, password } = req.body;
      if (!username || !password) {
        throw new ExpressError("username/password required", 400);
      }
      // has password
      const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR)
      // save to db? 
      const result = await db.query(
        `
        INSERT INTO users (
        username,
        password,
        first_name,
        last_name,
        phone,
        join_at,
        last_login_at)
        VALUES ($1, $2, $3, $4, $5, localtimestamp, current_timestamp)
        RETURNING username, first_name, last_name, phone
        `,
        [username, hashedPassword, first_name, last_name, phone]
      );
      return result.json(result.rows[0]);
    } catch (e) {
      if (e.code === '23505') {
        return next(new ExpressError("username taken? pick another", 400));
      }
      return next(e);
    }
   }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    try {
      const result = await db.query(
        `
        SELECT username, password
        FROM users
        WHERE username = $1
        `,
        [username]
      );
      const user = result.rows[0];
      // compare provided password with the hashed pw in the db
      if (user) {
        const isValidPassword = await bcrypt.compare(password, user.password);
        return isValidPassword;
      }
      return false; //no user found
    }
    catch (e) {
      throw new ExpressError('Authentication failed', 401);
    }
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    try {
      const result = await db.query(
        `
        UPDATE users
        SET last_login_at = current_timestamp
        WHERE username = $1
        `,
        [username]
      );
      const updatedUser = result.rows[0];
      if (!updatedUser) {
        throw new ExpressError('User not found', 404);
      }
      return updatedUser;
    }
    catch (e){
      return next (e);
    }
   }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    try {
      const results = await db.query(
        `
        SELECT *
        FROM users
        `
      )
    }
   }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) { }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) { }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) { }
}


module.exports = User;