import { Client } from "https://deno.land/x/postgres/mod.ts";
import { v4 } from 'https://deno.land/std/uuid/mod.ts'

import { dbCreds } from '../config.ts'

//init client
const client = new Client(dbCreds)




// @desc get goal
// @route GET /api/v1/goals/:id
const getGoalList = async ({ params, response }:
{ params: { id: string }, response: any }) => {
  try {
    await client.connect()

    const result = await client.query(`SELECT * FROM goals where user_id = ${params.id}`)
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
    console.log('goals', goals)

  } catch (err) {
    response.status = 500
    response.body = {
      success: false,
      msg: err.toString()
    }

  } finally { await client.end() }
}


export { getGoalList }