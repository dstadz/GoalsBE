import { Client } from "https://deno.land/x/postgres/mod.ts";
import { v4 } from 'https://deno.land/std/uuid/mod.ts'

import { dbCreds } from '../config.ts'

//init client
const client = new Client(dbCreds)


// @desc get user list
// @route GET /api/v1/users
const getUsers = async ({ response }:
  { response: any }) => {
  try {
    await client.connect()

    const result = await client.query("SELECT * FROM users")
    const users = new Array()

    result.rows.map(p => {
      let obj:any  = new Object()

      result.rowDescription.columns.map((el, i) => { obj[el.name] = p[i] })
      users.push(obj)
    })
    response.body = {
      success: true,
      data: users
    }
  } catch (err) {
    response.status = 500
    response.body = {
      success: false,
      msg: err.toString()
    }
  } finally { await client.end() }
}

// @desc get user
// @route GET /api/v1/users/:id
const getUser = async ({ params, response }:
  { params: { id: string }, response: any }) => {
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

// @desc add user
// @route Post /api/v1/users
const addUser = async ({ request, response }:
  { request: any, response: any }) => {
  const body = await request.body()
  const user = body.value

  if(!request.hasBody) {
    response.status = 404
    response.body = {
      success: false,
      msg: 'no data'
    }

  } else {
    try {
      await client.connect()
      const result = await client.query(`INSERT INTO users(name, email, birth)
      VALUES('${user.name}', '${user.email}','${user.birth}')`)

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

// @desc update user
// @route put /api/v1/users/:id
const updateUser = async ({ params, request, response }:
  { params: { id: string }, request:any, response: any }) => {
  await getUser({ params: {"id": params.id} , response})
  if (response.status === 404) {
    response.status = 404
    response.body = {
      success: false,
      msg: response.body
    }
    return;
  } else {
    const body = await request.body()
    const user = body.value

    if(!request.hasBody) {
      response.status = 404
      response.body = {
        success: false,
        msg: 'we messed up'
      }
    } else {
      try {
        await client.connect()

        const result = await client.query(`UPDATE users SET
          name='${user.name}',
          email='${user.email}',
          birth='${user.birth}'
          WHERE id=${params.id}`)

        response.status = 200
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
}
// @desc delete user
// @route delete /api/v1/users/:id
const deleteUser = async ({ params, response }:
  { params: { id:string }, response: any }) => {
  await getUser({ params: { "id": params.id } , response })

  if (response.status === 404) {
    response.status = 404
    response.body = {
      success: false,
      msg: response.body
    }
    return;

  } else {
    try {
      await client.connect()

      const result = await client.query(`DELETE FROM users WHERE id = ${params.id}`)
      response.status = 204
      response.body = {
        success: true,
        msg: `User ${params.id} has been deleted`
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

export { getUsers, getUser, addUser, updateUser, deleteUser }