import { Client } from "https://deno.land/x/postgres/mod.ts";
import { v4 } from 'https://deno.land/std/uuid/mod.ts'

import { dbCreds } from '../config.ts'

//init client
const client = new Client(dbCreds)


// @desc get goal list
// @route GET /api/v1/goals
const getGoals = async ({ response }:
  { response: any }) => {
  try {
    await client.connect()

    const result = await client.query("SELECT * FROM goals")
    const goals = new Array()

    result.rows.map(p => {
      let obj:any  = new Object()

      result.rowDescription.columns.map((el, i) => { obj[el.name] = p[i] })
      goals.push(obj)
    })
    response.body = {
      success: true,
      data: goals
    }
  } catch (err) {
    response.status = 500
    response.body = {
      success: false,
      msg: err.toString()
    }
  } finally { await client.end() }
}

// @desc get goal
// @route GET /api/v1/goals/:id
const getGoal = async ({ params, response }:
  { params: { id: string }, response: any }) => {
  try {
    await client.connect()
    const result = await client.query(`SELECT * FROM goals WHERE id = ${params.id}`)
    if ( result.rows.toString() === "") {
      response.status = 404
      response.body = {
        success: false,
        msg: `no goal with id ${params.id} found`
      }
      return;

    } else {
      const goal: any = new Object()
      result.rows.map(p => {
        result.rowDescription.columns.map((el, i) => { goal[el.name] =p[i] })

        response.body = {
          success: true,
          data:goal
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

// @desc add goal
// @route Post /api/v1/goals
const addGoal = async ({ request, response }:
  { request: any, response: any }) => {
  const body = await request.body()
  const goal = body.value

  if(!request.hasBody) {
    response.status = 404
    response.body = {
      success: false,
      msg: 'no data'
    }

  } else {
    try {
      await client.connect()
      const result = await client.query(`INSERT INTO goals(name, email, birth)
      VALUES('${goal.name}', '${goal.email}','${goal.birth}')`)

      response.status = 201
      response.body = {
        success: true,
        data: goal
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

// @desc update goal
// @route put /api/v1/goals/:id
const updateGoal = async ({ params, request, response }:
  { params: { id: string }, request:any, response: any }) => {
  await getGoal({ params: {"id": params.id} , response})
  if (response.status === 404) {
    response.status = 404
    response.body = {
      success: false,
      msg: response.body
    }
    return;
  } else {
    const body = await request.body()
    const goal = body.value

    if(!request.hasBody) {
      response.status = 404
      response.body = {
        success: false,
        msg: 'we messed up'
      }
    } else {
      try {
        await client.connect()

        const result = await client.query(`UPDATE goals SET
          name='${goal.name}',
          email='${goal.email}',
          birth='${goal.birth}'
          WHERE id=${params.id}`)

        response.status = 200
        response.body = {
          success: true,
          data: goal
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
// @desc delete goal
// @route delete /api/v1/goals/:id
const deleteGoal = async ({ params, response }:
  { params: { id:string }, response: any }) => {
  await getGoal({ params: { "id": params.id } , response })

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

      const result = await client.query(`DELETE FROM goals WHERE id = ${params.id}`)
      response.status = 204
      response.body = {
        success: true,
        msg: `Goal ${params.id} has been deleted`
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

export { getGoals, getGoal, addGoal, updateGoal, deleteGoal }