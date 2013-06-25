
#ifndef BM_EXCEPTIONS_H
#define BM_EXCEPTIONS_H

#include <exception>

class Exception : public std::exception
{
public:

    explicit Exception(const char* file, int line, const char* message) throw()
        : m_file(file), m_message(message), m_line(line) {}

    virtual ~Exception() throw() {}

    virtual const char*
    file() const throw() { return m_file; }

    virtual int
    line() const throw() { return m_line; }

    virtual const char*
    what() const throw() { return m_message; }

private:

    const char *m_file, *m_message;
    int m_line;
};

class Exception_PostFence : public Exception
{
public:

    explicit Exception_PostFence(const char* file, int line, const char* message) throw()
        : Exception(file, line, message) {}
    virtual ~Exception_PostFence() throw() {}
};

#endif
