/** User class for message.ly */

const db = require("../db");
const ExpressError = require("../expressError");
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require('../config');
const bcrypt = require('bcrypt');

/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) {
    // has password
    let hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR)
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
    return result.rows[0];
   }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(
      `
      SELECT password
      FROM users
      WHERE username = $1
      `,
      [username]
    );
    let user = result.rows[0];
    // compare provided password with the hashed pw in the db
    if (user) {
      const isValidPassword = await bcrypt.compare(password, user.password);
      return isValidPassword;
    }
    return false; //no user found

    // or return user && await bcrypt.compare(password, user.password);

  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
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
    // return updatedUser; // don't think this is needed?
   }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const results = await db.query(
      `
      SELECT 
        username,
        first_name,
        last_name,
        phone
      FROM users
      ORDER BY username
      `
      );
      return results = result.rows; // remember we're getting all here
   }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) { 
    const result = await db.query(
      `
      SELECT 
        username, 
        first_name, 
        last_name, 
        phone, 
        join_at,
        last_login_at
      FROM users
      WHERE username = $1
      `,
      [username]
    );
    if (!result.rows[0]) {
      throw new ExpressError(`no such user: ${username}`, 404);
    }
    return result.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) { 
    // command + option + arrow key to edit multiple lines
    // we're joining on to_username bc that's who's user info we want to select
    const results = await db.query(
    `
    SELECT 
      m.id,
      m.to_username,
      u.username,
      u.first_name,
      u.last_name,
      u.phone,
      m.body,
      m.sent_at,
      m.read_at
    FROM messages AS m
    JOIN users as u ON m.to_username = u.username
    WHERE m.from_username = $1
    `,
    [username]
    );

    return results.rows.map(m => ({
      id: m.id,
      to_user: {
        username: m.to_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at
    }));
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const results = await db.query(
      `
      SELECT 
        m.id,
        m.from_username,
        u.username,
        u.first_name,
        u.last_name,
        u.phone
        m.body,
        m.sent_at,
        m.read_at
      FROM messages AS m
      JOIN users as u ON u.username = m.from_username
      WHERE m.to_username = $1
      `,
      [username]
    );
    return results.rows.map(m => ({
      id: m.id,
      from_user: {
        username: m.username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at
    }))
  }
}


module.exports = User;