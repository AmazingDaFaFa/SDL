# STRCPY的内存溢出问题

## 程序测试代码  

```C
#define _CRT_SECLRE_NO_WARNINGS //编译时忽视错误

#include<stdlib.h>
#include<stdio.h>
#include<string.h>

int sub(char* x) {
  char y[10];
  strcpy(y, x);
  return 0;
}

int main(int argc, char** argv) {
  if (argc > 1)
     sub(argv[1]);
     printf("exit");
}
```

## VisualStudio配置  

- 在项目属性设置中，将“启用C++异常”设置为否，禁用“安全检查”  
![image](./img/img-1.png)  
- 禁用SDL检查  
![image](./img/img-2.png)  
- 修改“调试”的命令参数设置为任意字符串（此处为fffffffffffffffffffffff  
![image](./img/img-3.png)  

## 开始测试  

- 在strcpy函数前设置断点，然后编译程序  
- 启用“反汇编”，设置显示代码字符和地址
![image](./img/img-4.png)  
  - EAX，EBX，ECX，EDX——高低位寄存器，cpu主要操作的对象
  - ESP——栈顶指针，堆栈的顶部是地址小的区域，压入堆栈的数据越多，ESP也就越来越小。在32位平台上，ESP每次减少4字节。  
  - EBP——寄存器存放当前线程的栈底指针  
  - EIP——寄存器存放下一个CPU指令存放的内存地址，当CPU执行完当前的指令后，从EIP寄存器中读取下一条指令的内存地址，然后继续执行。  

- 当程序运行到断点位置时，EIP的地址与mov指令的地址相同  
![image](./img/img-5.png)  
  - 此时在内存中搜索EAX的值，可以看到该地值存储的即为预先输入的字符串
  ![image](./img/img-8.png)  
- 进入下一过程，EIP值变化，EAX此时存放源字符串的地址的值，EAX压入栈中，栈顶指针ESP减少一个单位  
![image](./img/img-6.png)  
- 接下来的三个过程中，EIP再次变化，ECX保存y的值，y值压入了栈中，栈顶指针ESP再减少4个字节  
![image](./img/img-7.png)  
- 此后，程序执行call指令，来到strcpy的代码区域，再次jump到strcpy的代码  
- 随后执行的mov操作，将EDX数据寄存器存放的从x中拿到的数据，移交给给ECX
![image](./img/img-9.png)  
- 继续执行代码，可以看到ECX中的值已经完成了拷贝，但EAX的部分已归还
![image](./img/img-10.png)  

## 实验结果

strcpy成功引发了溢出错误

## 错误分析

实验中在定义了x和y之后，因为y在栈中，存放于x之前，所以如果把x赋值给y，那么y在接受这个长字符串后，由于本身存储空间较小，但复制工作只负责全部转移，就会发生溢出现象，占用x的内存和后续其他内存空间  
如下图：

00 | 00 | 00 | 00 | 00 | \0 | f | f | f |
-|-|-|-|-|-|-|-|-
y |  |  |  |  |x |  

f | f | f | f | f | f | f | f | f |
-|-|-|-|-|-|-|-|-
y |  |  |  |  |x |  

将长字符串赋值给短字符串时，因为短字符串所占的内存空间不足，如果强行赋值，则会造成内存溢出现象，占用后续内存空间，可能造成数据丢失等现象

## 总结  

## 不要使用strcpy，尝试使用安全的的方法
