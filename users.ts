let users = [
  {
    id: '1',
    name: "bob",
  }
]

const getUsers = ({ response }: { response: any }) => {
  response.body = {
    success: true,
    data: users
  }
}

export { getUsers }