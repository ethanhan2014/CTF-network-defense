from subprocess import call
import sys

vulnerabilities = {"fmt_str": ["fprintf", "sprintf", "printf", "scanf"],
                   "strcpy": ["strcpy"],
                   "stack_overflow": ["strcat"],
                   "cmd_inject": ["execlp", "snprintf"]
                   }


def hack(filename):
    call(f"objdump -d {filename} > dump_file.txt", shell=True)
    with open("dump_file.txt", "r") as f:
        for line in f:
            for k, v in vulnerabilities.items():
                if set(v).intersection(line.split()):
                    print(f"{k} vulnerability found: {line}")


if __name__ == "__main__":
    # usage: python3 binary_analysis path_to_obj_file
    hack(sys.argv[1])
