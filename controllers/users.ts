import { v4 } from 'https://deno.land/std/uuid/mod.ts'
import { User } from '../types.ts'

//list of users
let users = [
  {
    id: '1',
    name: 'Bob1',
    email: 'bob@email.com',
    sign_up_date: 100000
  },{
    id: '2',
    name: 'Alice',
    email: 'A@lice.com',
    sign_up_date: 100001
  }
]

// @desc get user list
// @route GET /api/v1/users
const getUsers = ({ response }: { response: any }) => {
  response.body = {
    success: true,
    data: users
  }
}

// @desc get user
// @route GET /api/v1/users/:id
const getUser = ({ params, response }: { params: { id: string}, response: any }) => {
  const user: User | undefined = users.find(p => p.id === params.id)

  if (user) {
    response.status = 200
    response.body = {
      success: true,
      data: user
    }
  } else {
    response.status = 404
    response.body = {
      success: false,
      msg: 'item not found'
    }
  }
}

// @desc add user
// @route Post /api/v1/users
const addUser = async ({ request, response }: { request: any, response: any }) => {
  const body = await request.body()

  if(!request.hasBody) {
    response.status = 404
    response.body = {
      success: false,
      msg: 'no data'
    }
  } else {
    const user: User = body.value
    user.id = v4.generate()
    users.push(user)

    response.status = 200
    response.body = {
      success: true,
      data: user
    }
  }
}

// @desc update user
// @route put /api/v1/users/:id
const updateUser = async ({ params, request, response }: {  params: { id: string}, request:any, response: any }) => {
  const user: User | undefined = users.find(p => p.id === params.id)

  if (user) {
    const body = await request.body()
    const updataData: {name?:string, description?:string, price?:number } = body.value

    users = users.map(p => p.id ===params.id ? {...p, ...updataData } : p)
    response.status = 200
    response.body = {
      success: true,
      data: users
    }
  } else {
    response.status = 404
    response.body = {
      success: false,
      msg: 'item not found'
    }
  }
}
// @desc delete user
// @route delete /api/v1/users/:id
const deleteUser = ({ params, response }: { params: {id:string}, response: any }) => {
  users = users.filter(p => p.id != params.id)
  response.body = {
    success: true,
    msg: 'user removed'
  }
}

export { getUsers, getUser, addUser, updateUser, deleteUser }