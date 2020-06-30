import { Client } from "https://deno.land/x/postgres/mod.ts";
import { v4 } from 'https://deno.land/std/uuid/mod.ts'

import { dbCreds } from '../config.ts'

//init client
const client = new Client(dbCreds)


// @desc get habit list
// @route GET /api/v1/habits
const getHabits = async ({ response }:
  { response: any }) => {
  try {
    await client.connect()

    const result = await client.query("SELECT * FROM habits")
    const habits = new Array()

    result.rows.map(p => {
      let obj:any  = new Object()

      result.rowDescription.columns.map((el, i) => { obj[el.name] = p[i] })
      habits.push(obj)
    })
    response.body = {
      success: true,
      data: habits
    }
  } catch (err) {
    response.status = 500
    response.body = {
      success: false,
      msg: err.toString()
    }
  } finally { await client.end() }
}

// @desc get habit
// @route GET /api/v1/habits/:id
const getHabit = async ({ params, response }:
  { params: { id: string }, response: any }) => {
  try {
    await client.connect()
    const result = await client.query(`SELECT * FROM habits WHERE id = ${params.id}`)
    if ( result.rows.toString() === "") {
      response.status = 404
      response.body = {
        success: false,
        msg: `no habit with id ${params.id} found`
      }
      return;

    } else {
      const habit: any = new Object()
      result.rows.map(p => {
        result.rowDescription.columns.map((el, i) => { habit[el.name] =p[i] })

        response.body = {
          success: true,
          data:habit
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

const getHabitList = async ({ params, response }:
  { params: { id: string }, response: any }) => {
  try {
    await client.connect()

    const result = await client.query(`SELECT * FROM habits WHERE goal_id = ${params.id}`)
    const habits = new Array()

    result.rows.map(p => {
      let obj:any  = new Object()

      result.rowDescription.columns.map((el, i) => { obj[el.name] = p[i] })
      habits.push(obj)
    })
    response.body = {
      success: true,
      data: habits
    }
  } catch (err) {
    response.status = 500
    response.body = {
      success: false,
      msg: err.toString()
    }
  } finally { await client.end() }
}
// @desc add habit
// @route Post /api/v1/habits
const addHabit = async ({ request, response }:
  { request: any, response: any }) => {
  const body = await request.body()
  const habit = body.value
  console.log(habit)
  if(!request.hasBody) {
    response.status = 404
    response.body = {
      success: false,
      msg: 'no data'
    }

  } else {
    try {
      await client.connect()

      const result = await client.query(`INSERT INTO habits(goal_id, habit, amount, freq)
      VALUES('${habit.goal_id}','${habit.habit}','${habit.amount}','${habit.freq}')`)

      response.status = 201
      response.body = {
        success: true,
        data: habit
      }
    } catch (err) {
      console.log(err)
      response.status = 500
      response.body = {
        success: false,
        msg: err.toString()
      }
    } finally { await client.end() }
  }
}

// @desc update habit
// @route put /api/v1/habits/:id
const updateHabit = async ({ params, request, response }:
  { params: { id: string }, request:any, response: any }) => {
  await getHabit({ params: {"id": params.id} , response})
  if (response.status === 404) {
    response.status = 404
    response.body = {
      success: false,
      msg: response.body
    }
    return;
  } else {
    const body = await request.body()
    const habit = body.value

    if(!request.hasBody) {
      response.status = 404
      response.body = {
        success: false,
        msg: 'we messed up'
      }
    } else {
      try {
        await client.connect()

        const result = await client.query(`UPDATE habits SET

          habit='${habit.habit}',
          amount='${habit.amount}',
          freq='${habit.freq}'
          WHERE id=${params.id}`)

        response.status = 200
        response.body = {
          success: true,
          data: habit
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
// @desc delete habit
// @route delete /api/v1/habits/:id
const deleteHabit = async ({ params, response }:
  { params: { id:string }, response: any }) => {
  await getHabit({ params: { "id": params.id } , response })

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

      const result = await client.query(`DELETE FROM habits WHERE id = ${params.id}`)
      response.status = 204
      response.body = {
        success: true,
        msg: `Habit ${params.id} has been deleted`
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

export { getHabits, getHabitList, getHabit, addHabit, updateHabit, deleteHabit }