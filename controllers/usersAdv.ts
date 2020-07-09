import { Client } from "https://deno.land/x/postgres/mod.ts";
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts";

import { v4 } from 'https://deno.land/std/uuid/mod.ts'

import { dbCreds } from '../config.ts'

//init client
const client = new Client(dbCreds)

const signIn = async ({ params, response }: { params: { id: string }, response: any }) => {
  console.log(`get user ${params.id}`)
  try {
    await client.connect()
    const result = await client.query(`SELECT * FROM users WHERE id = ${params.id}`)
    if ( result.rows.toString() === "") {
      response.status = 404
      response.body = {
        success: false,
        msg: `no user with id ${params.id} found`
      }
      return;

    } else {
      const user: any = new Object()
      result.rows.map(p => {
        result.rowDescription.columns.map((el, i) => { user[el.name] =p[i] })
        response.body = {
          success: true,
          data:user
        }
      })
    }

  } catch (err) {
    response.status = 500
    response.body = {
      success: false,
      msg: err.toString()
    }
  } finally { await client.end() }
}

const signUp = async ({ request, response }: { request: any, response: any }) => {
  const body = await request.body()
  const user = body.value


  const salt = bcrypt.genSaltSync(8);
  const hash = bcrypt.hashSync("Type Data you want to hash", salt);

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
