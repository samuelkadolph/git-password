# Store your git https passwords in your OS X Keychain

Around this time last year git added a [“smart” HTTP transport](https://github.com/blog/642-smart-http-support) that is faster than the old HTTP transport (and in some cases faster than SSH too). And a few months later [GitHub added support for this new HTTP transport](https://github.com/blog/642-smart-http-support) and made it the default selected url for repositories (that you aren’t a contributor for).

There aren’t any major advantages using https over ssh to access your GitHub repositories, it’s just more simple to use your username/password instead of adding your ssh key. The only other advantages is that it’s easier to set up HTTP proxy for git (git config --global http.proxy proxy:8080 vs ssh config) and being able to use more than one GitHub account (which you shouldn’t since anyone can add you as a contributor to a project).

One major disadvantage is that it asks you for your username/password each time you interact with your remote repository (clone, pull, push, etc). To solve this, I decided to write a program that stores your username and/or password in your keychain so git will ask once for you username/password and retrieve it later so you don’t have to type it again. 

* [blog post](http://samuel.kadolph.com/2011/03/store-your-git-https-passwords-in-your-os-x-keychain/)
* 

## Quickstart 

The final fruit of my endeavour is a program called `git-password`, [binary available here](https://github.com/downloads/samuelkadolph/git-password/git-password). It was written in Xcode 4 and the [source is available here](https://github.com/samuelkadolph/git-password).

To use the program first you need to download it and make it executable.

```bash
    curl -L http://bit.ly/git-password > ~/git-password
    chmod +x ~/git-password
```

And now depending on your version of git you have 2 different ways of making git use the program.

Git 1.7.3 and above:

```bash
    git config --global core.askpass ~/git-password
```    

Git 1.7.2 and below:

```bash
    echo export GIT_ASKPASS="$HOME/git-password" >> .bash_profile
```    
    
And now just go and clone any https repository or update the url of your remotes.

![Using git-password to remember git https passwords in your keychain](http://samuel.kadolph.com/wp-content/uploads/2011/03/Screen-shot-2011-03-25-at-2.50.24-PM.png)

## Backstory

### Learning

I started writing this program using ruby and some [system](http://www.ruby-doc.org/core/classes/Kernel.html#M001441) calls to the security command line tool. But to store a password in your keychain using this tool you have to pass it as an argument to security which means anyone on the system can see this if they know were to look. This quickly ruled out using the security tool so I had to look at using the keychain api natively.

My next step was to search for a gem that wrapped the C api for me so I don’t have to get my hand dirty in C. I found the [mac-keychain gem](https://github.com/xli/mac-keychain/) and later heard about [zenspider’s gem osx_keychain](https://github.com/seattlerb/osx_keychain). Using native C functions to add the password prevents it from being available in plaintext to other processes which fixes that problem. But I quickly found another problem.

Each OS X Keychain item has a list of authorized applications that can read the password from the item without the user being prompted.

![Mac OS X Keychain Item Access Control](http://samuel.kadolph.com/wp-content/uploads/2011/03/Screen-shot-2011-03-25-at-1.41.38-PM.png)

When you add an item to the keychain unless you otherwise specify, the current application running is implicitly the only authorized application. This makes sense because you store passwords to be able to recover their plaintext later (otherwise you should be using a [key derivation function](http://en.wikipedia.org/wiki/Key_derivation_function) like [bcrypt](http://en.wikipedia.org/wiki/Bcrypt) or [scrypt](http://www.tarsnap.com/scrypt.html)).

The problem is that when you call the native C functions from inside ruby, ruby is the application that is running (your code is just a script that Keychain is unaware of). So this means that any ruby script can freely retrieve the passwords stored by other ruby scripts (and thus enable a rarely large security flaw with your program) without the user being prompted to give permission.

![Mac OS X Keychain prompt](http://samuel.kadolph.com/wp-content/uploads/2011/03/Screen-shot-2011-03-25-at-1.40.06-PM.png)

So I had to scrap the idea of using ruby and write my own C program to do it. This would prevent anyone from running code on the computer and being able to freely retrieve passwords stored by my application (along with the application names, a signature is stored so if someone wrote their own application with the same name, it would still prompt the user for access).

The next step was to confirm that git was the one that was calling the program so someone cannot do git-password "Password: " inside of a git repository and have the program give the password up. I took a while but I finally found some [sample code that shows how to get the list of processes on OS X](http://developer.apple.com/library/mac/#qa/qa2001/qa1123.html) and that combined with [getppid](http://developer.apple.com/library/mac/#documentation/Darwin/Reference/ManPages/man2/getppid.2.html) allows me to [check that git was the program that started us](https://github.com/samuelkadolph/git-password/blob/9c25e65644e3e7b768054fb20aa5414393d236c0/git-password/main.c#L55-73) (technically it’s git-remote-https).
