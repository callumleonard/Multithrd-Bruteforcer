#include <chrono>
#include <iostream>
#include <iomanip>
#include <amp.h>
#include <time.h>
#include <string>
#include <array>
#include <limits>
#include <assert.h>
#include <fstream>
#include <thread>
#include <stdlib.h>
#include <map>

typedef std::chrono::steady_clock the_clock;
using std::chrono::duration_cast;
using std::chrono::milliseconds;

bool writeFlag = false;
size_t userpassword_hash;
std::vector<size_t> hashed_Vector(2172000, 0);
std::vector<std::string> unhashed_Vector;
std::mutex othermutex; 
std::condition_variable condition;
std::mutex mymutex;
std::unique_lock<std::mutex> lock(mymutex);

void user_passwordHash()
{
	std::string user_passwordInput = " ";
	std::cout << "Enter password to be bruteforced: ";
	std::cin >> user_passwordInput;
	std::cout << std::endl;
	std::cout << "Bruteforcing..." << std::endl;
	std::cout << "Bruteforcing..." << std::endl;
	std::cout << "" << std::endl;
	std::cout << "Note: Thread output below may not be displayed sequentially (normal output).";
	std::cout << "" << std::endl;
	std::hash<std::string> hash_fn;
	std::size_t str_hash = hash_fn(user_passwordInput);
	userpassword_hash = str_hash;
}

void single_bruteforce(int linetotal)
{
	the_clock::time_point start = the_clock::now();
	for (int i = 0; i <= linetotal; i++)
	{
		if (userpassword_hash == hashed_Vector[i])
		{
			std::cout << "" << std::endl;
			std::cout << "\x1B[32m[Thread \033[0m" << 1 << "\x1B[32m]:\033[0m" << "\x1B[32m Bruteforce successful.\033[0m" << "| Bruteforced password: " << unhashed_Vector[i];
			std::cout << "" << std::endl;
			the_clock::time_point end = the_clock::now();
			auto time_taken = duration_cast<milliseconds>(end - start).count();
			std::cout << "Standard Bruteforce Time: " << time_taken << " ms." << std::endl;
			std::cout << std::endl;
			return;
		}
	}
	std::cout << "\x1B[32m[Thread \033[0m" << 1 << "\x1B[32m]:\033[0m" << "\x1B[31m Unable to bruteforce password via dictionary attack.\033[0m" << std::endl;
}

void populate_vector(int linetotal)
{
	std::ifstream dictionaryList("wordlist.txt");
	std::string text;
	std::cout << std::endl;
	std::cout << "\x1B[33mPopulating Vector, Please Wait...\033[0m" << std::endl;

	the_clock::time_point start1 = the_clock::now();
	for (int i = 0; i <= linetotal; i++)
	{
		(std::getline(dictionaryList, text));
		unhashed_Vector.push_back(text);
	}
	writeFlag = true; //indicates that all text has been pushed onto the vector
	condition.notify_all(); //notify all threads that vector has been written to
	if (writeFlag == true)
	{
		std::cout << "\x1B[32mSuccessful.\033[0m" << std::endl;
		the_clock::time_point end1 = the_clock::now();
		auto time_taken1 = duration_cast<milliseconds>(end1 - start1).count();
		std::cout << "Vector Population Time: " << time_taken1 << " ms." << std::endl;
	}
	else
	{
		std::cout << "Vector Error, Exiting...", exit(0);
	}
	std::cout << std::endl;
	std::cout << "\x1B[33mHashing Password File, Please Wait...\033[0m" << std::endl;
}

void dictionaryHash(int start, int devidedLines, int linetotal, int thread_ID)
{
	bool hashFlag = false;
	while (writeFlag != true) //endlessly loop/wait until condition met. Once met threads can concurrently hash
	{
		condition.wait(lock);
	}

	if (start > 0 && start == devidedLines * 1)
	{
		for (int i = 0; i < devidedLines * 1; i++)
		{
			auto temp = unhashed_Vector[i];
			std::hash<std::string> hash_fn;
			std::size_t str_hash = hash_fn(temp);
			auto hashed_text = str_hash;
			othermutex.lock();
			hashed_Vector[i] = hashed_text;
			othermutex.unlock();
		}
	}

	if (start > devidedLines * 1 && start == devidedLines * 2)
	{
		for (int i = devidedLines * 1; i <= devidedLines * 2; i++)
		{
			auto temp = unhashed_Vector[i];
			std::hash<std::string> hash_fn;
			std::size_t str_hash = hash_fn(temp);
			auto hashed_text = str_hash;
			othermutex.lock();
			hashed_Vector[i] = hashed_text;
			othermutex.unlock();
		}
	}
	hashFlag = true;
	if (hashFlag == true)
	{
		std::cout << "\x1B[32m[Thread \033[0m" << thread_ID << "\x1B[32m]:\033[0m" << "\x1B[32mSuccessful.\033[0m" << std::endl;
	}
	else
	{
		std::cout << "Hash Computation Error, Exiting...", exit(0);
	}
}

void populate_hashThrds(int totalLines)
{
	std::thread hashThreads[2];
	int start = 0;
	int const devidedLines = totalLines / 2;
	int thread_ID = 0;
	std::thread populateThread(populate_vector, totalLines);
	populateThread.join();
	the_clock::time_point start1 = the_clock::now();
	for (int i = 0; i < 2; i++)
	{
		thread_ID++;
		start = start + devidedLines;
		hashThreads[i] = std::thread(dictionaryHash, start, devidedLines, totalLines, thread_ID);
	}
	for (int i = 0; i < 2; i++)
	{
		hashThreads[i].join();
	}
	the_clock::time_point end1 = the_clock::now();
	auto time_taken1 = duration_cast<milliseconds>(end1 - start1).count();
	std::cout << "File Hash Time: " << time_taken1 << " ms." << std::endl;
	Sleep(3500);
	system("CLS");
}

void multiThrd_bruteforce(int start, int const constValue, int linetotal, int thread_ID)
{
	for (int i = start - constValue; i < start; i++)
	{
		if (userpassword_hash == hashed_Vector[i])
		{
			std::cout << "\x1B[32m[Thread \033[0m" << thread_ID << "\x1B[32m]:\033[0m" << "\x1B[32m Bruteforce successful.\033[0m" << "| Bruteforced password: " << unhashed_Vector[i] << std::endl;
		
			return;
		}
	}
	othermutex.lock(); //mitigates results being displayed on the same line if multiple threads run statement line (184) concurrently.
	std::cout << "\x1B[32m[Thread \033[0m" << thread_ID << "\x1B[32m]:\033[0m" << "\x1B[31m Unable to bruteforce password via dictionary attack.\033[0m" << std::endl;
	othermutex.unlock();
} 

void spool_multiBrute(int totalLines)
{
	std::thread bruteThreads[6];
	int start = 0;
	int const constValue = totalLines / 6 + 1;
	int thread_ID = 0;
	the_clock::time_point start1 = the_clock::now();
	for (int i = 0; i < 6; i++)
	{
		start = start + constValue;
		thread_ID++;
		bruteThreads[i] = std::thread(multiThrd_bruteforce, start, constValue, totalLines, thread_ID);
	}
	for (int i = 0; i < 6; i++)
	{
		bruteThreads[i].join();
	}
	the_clock::time_point end1 = the_clock::now();
	auto time_taken1 = duration_cast<milliseconds>(end1 - start1).count();
	std::cout << "Multi-threaded Bruteforce Time: " << time_taken1 << " ms." << std::endl;
	std::cout << "" << std::endl;
}

void menu(int& linetotal)
{
	int menu;

	std::cout << R"(     
-------------------------------------------------------------
		                                        
           (                
            )              
       __.--(--.         
      || |     |         
       \\|     |        
        \.     .        
          `---'         
------------------------
+ Callum's Bruteforcer +
------------------------
	       
This program is a working concept 
demonstrating bruteforce capability,
and speed only, and not against accounts.

Note: This program could be easily applied
to bruteforce accounts.        
    
1)Bruteforce Standard | Slow
2)Bruteforce Multi-threaded | Fast
3)Exit

INFO: Our dictionary wordlist contains 2.1 million passwords!

------------------------------------------------------------- )" << '\n';
	std::cout << "Enter choice: ";
	std::cin >> menu;

	switch (menu)
	{
	case 1: populate_hashThrds(linetotal), user_passwordHash(), single_bruteforce(linetotal);
		break;
	case 2: populate_hashThrds(linetotal), user_passwordHash(), spool_multiBrute(linetotal);
		break;
	case 3: std::cout << "Exiting..." << std::endl, exit(0);
		break;
	default:
		while (!(std::cin >> menu && menu < 1 && menu > 3))
		{
			std::cout << "Invalid input, only enter number 1,2 or 3." << std::endl;
			std::cout << R"(     
 -------------------------------------------------------------
		                                        
           (                
            )              
       __.--(--.         
      || |     |         
       \\|     |        
        \.     .        
          `---'         
------------------------
+ Callum's Bruteforcer +
------------------------
	       
This program is a working concept 
demonstrating bruteforce capability,
and speed only, and not against accounts.

Note: This program could be easily applied
to bruteforce accounts.        
    
1)Bruteforce Standard | Slow
2)Bruteforce Multi-threaded | Fast
3)Exit

INFO: Our dictionary wordlist contains 2.1 million passwords!

-------------------------------------------------------------  )" << '\n';
			std::cout << "Enter Choice: " << std::endl;
			switch (menu)
			{
			case 1: populate_hashThrds(linetotal), user_passwordHash(), single_bruteforce(linetotal);
				break;
			case 2: populate_hashThrds(linetotal), user_passwordHash(), spool_multiBrute(linetotal);
				break;
			case 3: std::cout << "Exiting..." << std::endl, exit(0);
				break;
			}
			std::cin.clear();
			std::cin.ignore();
		}
	}
}

int calculate_length(int &linetotal)
{
	std::string text;
	bool lengthFlag = false;
	std::ifstream dictionaryList("wordlist.txt");
	std::cout << "Calculating Length of Dictionary File, Please Wait..." << std::endl;
;
	for (int i = 0; (std::getline(dictionaryList, text)); i++)
	{
		linetotal++;
	}
	lengthFlag = true;
	if (lengthFlag == true)
	{
		std::cout << "Successful." << std::endl;
	}
	else
	{
		std::cout << "Unable to Calculate Length, Exiting...", exit(0);
	}
	return linetotal;
}
int main()
{
	int linetotal = 0;
	calculate_length(linetotal);
	Sleep(1250);
	system("CLS");
	menu(linetotal);
	return 0;
}