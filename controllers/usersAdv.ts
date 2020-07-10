import { Client } from "https://deno.land/x/postgres/mod.ts";
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts";

import { v4 } from 'https://deno.land/std/uuid/mod.ts'

import { dbCreds } from '../config.ts'

//init client
const client = new Client(dbCreds)

const signIn = async ({ request, response }: { request: any, response: any }) => {
  console.log('attempt!')

  const body = await request.body()
  const user = body.value

  console.log('body:', body)

  if(!request.hasBody) {
    response.status = 404
    response.body = {
      success: false,
      msg: 'no data'
    }
  } else {
    try {
      console.log('post-try')
      await client.connect()
      const { email, password } = body.value

      const result = await client.query(`SELECT * FROM users WHERE email = '${email}'`)

      if ( result.rows.toString() === "") {
        response.status = 404
        response.body = {
          success: false,
          msg: `no user with email ${email} found`
        }
        return;

      } else {
        const user: any = new Object()
        result.rows.map(p => {
          result.rowDescription.columns.map((el, i) => {
            user[el.name] = p[i]})
        })

        const comp = await bcrypt.compare(password, user.password)
        if ( comp ) {
          response.body = {
            success: true,
            data:user
          }
        } else {
          response.status = 403
          response.body = {
            success: false,
            msg: 'Wrong password'
          }
        }

      }
    } catch (err) {
      response.status = 500
      response.body = {
        success: false,
        msg: err.toString()
      }
    } finally { await client.end() }
  }
}

const signUp = async ({ request, response }: { request: any, response: any }) => {
  const body = await request.body()
  const user = body.value

  const hash = bcrypt.hashSync(user.password);

  if(!request.hasBody) {
    response.status = 404
    response.body = {
      success: false,
      msg: 'no data'
    }

  } else {
    try {
      await client.connect()
      const result = await client.query(`INSERT INTO users(name, email, birthday, password)
      VALUES('${user.name}', '${user.email}','${user.birthday}','${hash}')`)

      response.status = 201
      response.body = {
        success: true,
        data: user
      }
    } catch (err) {
      response.status = 500
      response.body = {
        success: false,
        msg: err.toString()
      }
    } finally { await client.end() }
  }
}

const forgotPassword = null

export { signIn, signUp, forgotPassword }
