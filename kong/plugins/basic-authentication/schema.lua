return {
  name = 'basic-authentication',
  fields = {
    {
      config = {
        type = 'record',
        fields = {
          { username = { type = "string", required = true } },
          { password = { type = "string", required = true } }
        }
      }
    }
  }
}