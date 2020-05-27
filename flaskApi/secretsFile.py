# Private items
items = {
  # NOTE: "appConfigSecretKey"
  #       Use 'secrets.token_hex(16)' to generate it.
  "appConfigSecretKey": "",
  # NOTE: "mailServer"
  "mailServer": "",
  # NOTE: "mailPort"
  "mailPort": 587,
  # NOTE: "mailEmail"
  "mailEmail": "",
  # NOTE: "mailUsername"
  "mailUsername": "",
  # NOTE: "mailPassword"
  "mailPassword": "",
  # NOTE: "classTimezones"
  #       Must be valid names from pytz.
  #       Use 'pytz.all_timezones' to list them.
  #       Need to be in the format "('abc','abc')" due to wtforms SelectField.
  "classTimezones": [("Europe/Dublin","Europe/Dublin"), ("Europe/Berlin","Europe/Berlin"), ("US/Pacific","US/Pacific"), ("US/Central","US/Central"), ("US/Eastern","US/Eastern")]
}

# Return specified item
def getItem(key):
  try:
    return items.get(key)
  except:
    return "KEY_ERROR"