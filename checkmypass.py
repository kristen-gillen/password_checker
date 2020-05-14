import requests
import hashlib #built in module to convert to SH-1
import sys

#function to use API and get the API Data, give it the hashed version of our password
def request_api_data(query_char):
  url = 'https://api.pwnedpasswords.com/range/' + query_char
  res = requests.get(url) #response from the API
  if res.status_code != 200: #this is what should be returned based on API
    raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
  return res

#Function to check the count, receives the hashes/response and our hash to check, loop through them
def get_password_leaks_count(hashes, hash_to_check):
  hashes = (line.split(':') for line in hashes.text.splitlines()) # split everything in line by :, for each line in hashes.txt, split lines 
  for h, count in hashes:
    if h == hash_to_check: 
      return count
  return 0

#Function to check password and we want to check if password exists in API response
def pwned_api_check(password):
  #conversion to sh-1
  sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper() #just the format to do this, google or read API, needs to be upper case, hexdigest returns string of hex digits
  #Only need first five  characters, this splits them for later use
  first5_char, tail = sha1password[:5], sha1password[5:] #start up to 5th character, then remaining, tail is hash to check
  response = request_api_data(first5_char) #call above function with our characters, response is a long list of how many times
  return get_password_leaks_count(response, tail) #run the function with the response and hash to check (our tail)

def main(args):
  for password in args:
    count = pwned_api_check(password) #loop through and have sh-1 password, and we receieve count from the function
    if count:
      print(f'{password} was found {count} times... you should probably change your password!')
    else:
      print(f'{password} was NOT found. Carry on!')
  return 'done!'

if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
